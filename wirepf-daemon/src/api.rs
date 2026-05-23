use crate::bpf;
use crate::config::{InterfaceCfg, Mapping};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use std::net::Ipv4Addr;
use wirepf_common::dto::{CreateIfaceBody, Health, IfaceView};

pub fn router(state: AppState) -> Router {
    let mutating = Router::new()
        .route("/interfaces", post(create_iface))
        .route("/interfaces/{name}", delete(delete_iface))
        .route("/interfaces/{name}/mappings", post(create_mapping))
        .route("/interfaces/{name}/mappings/{orig}", delete(delete_mapping))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/health", get(health))
        .route("/interfaces", get(list_ifaces))
        .route("/interfaces/{name}/mappings", get(list_mappings))
        .merge(mutating)
        .with_state(state)
}

async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

fn iface_view(c: &InterfaceCfg) -> IfaceView {
    IfaceView {
        name: c.name.clone(),
        mappings: c.mappings.clone(),
    }
}

async fn list_ifaces(State(state): State<AppState>) -> Json<Vec<IfaceView>> {
    let inner = state.inner.lock().await;
    Json(inner.config.interfaces.iter().map(iface_view).collect())
}

async fn list_mappings(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<Mapping>>, ApiError> {
    let inner = state.inner.lock().await;
    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    Ok(Json(iface.mappings.clone()))
}

async fn create_iface(
    State(state): State<AppState>,
    Json(body): Json<CreateIfaceBody>,
) -> Result<Json<IfaceView>, ApiError> {
    let mut inner = state.inner.lock().await;

    if inner.config.find_iface(&body.name).is_some() {
        return Err(ApiError::conflict(format!(
            "interface {} already exists",
            body.name
        )));
    }

    let attached = bpf::attach(&body.name)
        .map_err(|e| ApiError::internal(format!("attach {}: {:?}", body.name, e.to_string())))?;
    inner.attached.insert(body.name.clone(), attached);

    let cfg = InterfaceCfg {
        name: body.name.clone(),
        mappings: Vec::new(),
    };
    inner.config.interfaces.push(cfg.clone());
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {}", e.to_string())))?;

    Ok(Json(iface_view(&cfg)))
}

async fn delete_iface(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut inner = state.inner.lock().await;

    if inner.config.find_iface(&name).is_none() {
        return Err(ApiError::not_found(format!("interface {name}")));
    }

    inner.attached.remove(&name);
    inner.config.interfaces.retain(|i| i.name != name);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn create_mapping(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mapping): Json<Mapping>,
) -> Result<Json<Mapping>, ApiError> {
    let mut inner = state.inner.lock().await;

    if inner.config.find_iface(&name).is_none() {
        return Err(ApiError::not_found(format!("interface {name}")));
    }

    if mapping.orig == mapping.new {
        return Err(ApiError::conflict(format!(
            "orig and new must differ ({})",
            mapping.orig
        )));
    }

    for iface in &inner.config.interfaces {
        for m in &iface.mappings {
            if m.orig == mapping.orig {
                return Err(ApiError::conflict(format!(
                    "orig {} already mapped on interface {}",
                    mapping.orig, iface.name
                )));
            }
            if m.new == mapping.new {
                return Err(ApiError::conflict(format!(
                    "target {} already used by orig {} on interface {}",
                    mapping.new, m.orig, iface.name
                )));
            }
        }
    }

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    bpf::insert_mapping(attached, mapping.orig, mapping.new)
        .map_err(|e| ApiError::internal(format!("ebpf insert: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.mappings.push(mapping);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(Json(mapping))
}

async fn delete_mapping(
    State(state): State<AppState>,
    Path((name, orig)): Path<(String, Ipv4Addr)>,
) -> Result<StatusCode, ApiError> {
    let mut inner = state.inner.lock().await;

    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    let mapping = iface
        .mappings
        .iter()
        .find(|m| m.orig == orig)
        .copied()
        .ok_or_else(|| ApiError::not_found(format!("mapping {orig}")))?;

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    bpf::remove_mapping(attached, mapping.orig, mapping.new)
        .map_err(|e| ApiError::internal(format!("ebpf remove: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.mappings.retain(|m| m.orig != orig);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn require_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, ApiError> {
    let configured = {
        let inner = state.inner.lock().await;
        inner.config.auth_token.clone()
    };
    let Some(expected) = configured.filter(|t| !t.is_empty()) else {
        return Err(ApiError::unauthorized("auth_token not configured"));
    };
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if supplied != expected {
        return Err(ApiError::unauthorized("invalid token"));
    }
    Ok(next.run(req).await)
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
    fn internal(m: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
    fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
