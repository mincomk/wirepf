use crate::bpf;
use crate::config::{Cidr, DnatMapping, InterfaceCfg, MasqueradeCfg, SnatMapping};
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use std::net::Ipv4Addr;
use wirepf_common::dto::{CreateIfaceBody, Health, IfaceView};

pub fn router(state: AppState) -> Router {
    let mutating = Router::new()
        .route("/interfaces", post(create_iface))
        .route("/interfaces/{name}", delete(delete_iface))
        .route("/interfaces/{name}/dnat", post(create_dnat))
        .route("/interfaces/{name}/dnat/{orig}", delete(delete_dnat))
        .route("/interfaces/{name}/snat", post(create_snat))
        .route("/interfaces/{name}/snat/{orig}", delete(delete_snat))
        .route("/interfaces/{name}/masquerade", put(put_masquerade))
        .route("/interfaces/{name}/refresh-ip", post(refresh_iface_ip))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .route("/health", get(health))
        .route("/interfaces", get(list_ifaces))
        .route("/interfaces/{name}/dnat", get(list_dnat))
        .route("/interfaces/{name}/snat", get(list_snat))
        .route("/interfaces/{name}/masquerade", get(get_masquerade))
        .merge(mutating)
        .with_state(state)
}

async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

fn iface_view(c: &InterfaceCfg, iface_ip: Option<Ipv4Addr>) -> IfaceView {
    IfaceView {
        name: c.name.clone(),
        dnat: c.dnat.clone(),
        snat: c.snat.clone(),
        masquerade: c.masquerade.clone(),
        iface_ip,
    }
}

async fn list_ifaces(State(state): State<AppState>) -> Json<Vec<IfaceView>> {
    let inner = state.inner.lock().await;
    let views = inner
        .config
        .interfaces
        .iter()
        .map(|i| {
            let ip = inner.attached.get(&i.name).and_then(|a| a.iface_ip);
            iface_view(i, ip)
        })
        .collect();
    Json(views)
}

async fn list_dnat(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<DnatMapping>>, ApiError> {
    let inner = state.inner.lock().await;
    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    Ok(Json(iface.dnat.clone()))
}

async fn list_snat(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<SnatMapping>>, ApiError> {
    let inner = state.inner.lock().await;
    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    Ok(Json(iface.snat.clone()))
}

async fn get_masquerade(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<MasqueradeCfg>, ApiError> {
    let inner = state.inner.lock().await;
    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    Ok(Json(iface.masquerade.clone()))
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
    let iface_ip = attached.iface_ip;
    inner.attached.insert(body.name.clone(), attached);

    let cfg = InterfaceCfg {
        name: body.name.clone(),
        dnat: Vec::new(),
        snat: Vec::new(),
        masquerade: MasqueradeCfg::default(),
    };
    inner.config.interfaces.push(cfg.clone());
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {}", e.to_string())))?;

    Ok(Json(iface_view(&cfg, iface_ip)))
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

async fn create_dnat(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mapping): Json<DnatMapping>,
) -> Result<Json<DnatMapping>, ApiError> {
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
        for m in &iface.dnat {
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
    bpf::insert_dnat(attached, mapping)
        .map_err(|e| ApiError::internal(format!("ebpf insert dnat: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.dnat.push(mapping);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(Json(mapping))
}

async fn delete_dnat(
    State(state): State<AppState>,
    Path((name, orig)): Path<(String, Ipv4Addr)>,
) -> Result<StatusCode, ApiError> {
    let mut inner = state.inner.lock().await;

    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    let mapping = iface
        .dnat
        .iter()
        .find(|m| m.orig == orig)
        .copied()
        .ok_or_else(|| ApiError::not_found(format!("dnat {orig}")))?;

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    bpf::remove_dnat(attached, mapping)
        .map_err(|e| ApiError::internal(format!("ebpf remove dnat: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.dnat.retain(|m| m.orig != orig);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn create_snat(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(mapping): Json<SnatMapping>,
) -> Result<Json<SnatMapping>, ApiError> {
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

    if let Some(iface) = inner.config.find_iface(&name)
        && iface.snat.iter().any(|m| m.orig == mapping.orig)
    {
        return Err(ApiError::conflict(format!(
            "snat orig {} already mapped on interface {name}",
            mapping.orig
        )));
    }

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    bpf::insert_snat(attached, mapping)
        .map_err(|e| ApiError::internal(format!("ebpf insert snat: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.snat.push(mapping);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(Json(mapping))
}

async fn delete_snat(
    State(state): State<AppState>,
    Path((name, orig)): Path<(String, Ipv4Addr)>,
) -> Result<StatusCode, ApiError> {
    let mut inner = state.inner.lock().await;

    let iface = inner
        .config
        .find_iface(&name)
        .ok_or_else(|| ApiError::not_found(format!("interface {name}")))?;
    let mapping = iface
        .snat
        .iter()
        .find(|m| m.orig == orig)
        .copied()
        .ok_or_else(|| ApiError::not_found(format!("snat {orig}")))?;

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    bpf::remove_snat(attached, mapping)
        .map_err(|e| ApiError::internal(format!("ebpf remove snat: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.snat.retain(|m| m.orig != orig);
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn put_masquerade(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(cfg): Json<MasqueradeCfg>,
) -> Result<Json<MasqueradeCfg>, ApiError> {
    validate_cidrs(&cfg.src_cidrs)?;

    let mut inner = state.inner.lock().await;

    if inner.config.find_iface(&name).is_none() {
        return Err(ApiError::not_found(format!("interface {name}")));
    }

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    if cfg.enabled && attached.iface_ip.is_none() {
        return Err(ApiError::conflict(format!(
            "cannot enable masquerade on {name}: interface IP unresolved (try POST /interfaces/{name}/refresh-ip)"
        )));
    }
    bpf::set_masquerade(attached, &cfg)
        .map_err(|e| ApiError::internal(format!("ebpf set masquerade: {e}")))?;

    let iface = inner.config.find_iface_mut(&name).unwrap();
    iface.masquerade = cfg.clone();
    inner
        .config
        .save_atomic(&state.config_path)
        .map_err(|e| ApiError::internal(format!("save config: {e}")))?;

    Ok(Json(cfg))
}

async fn refresh_iface_ip(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<IfaceView>, ApiError> {
    let mut inner = state.inner.lock().await;

    if inner.config.find_iface(&name).is_none() {
        return Err(ApiError::not_found(format!("interface {name}")));
    }

    let attached = inner
        .attached
        .get_mut(&name)
        .ok_or_else(|| ApiError::internal(format!("interface {name} not attached")))?;
    let ip = bpf::refresh_iface_ip(attached, &name)
        .map_err(|e| ApiError::internal(format!("refresh iface ip: {e}")))?;

    // Re-apply masquerade in case enabled state was suppressed by missing IP previously.
    let masq = inner
        .config
        .find_iface(&name)
        .map(|i| i.masquerade.clone())
        .unwrap_or_default();
    let attached = inner.attached.get_mut(&name).unwrap();
    bpf::set_masquerade(attached, &masq)
        .map_err(|e| ApiError::internal(format!("re-apply masquerade: {e}")))?;

    let iface = inner.config.find_iface(&name).unwrap();
    Ok(Json(iface_view(iface, ip)))
}

fn validate_cidrs(cidrs: &[Cidr]) -> Result<(), ApiError> {
    for c in cidrs {
        if c.prefix_len > 32 {
            return Err(ApiError::conflict(format!(
                "invalid prefix_len {} for {}",
                c.prefix_len, c.addr
            )));
        }
    }
    Ok(())
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
