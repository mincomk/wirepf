use anyhow::{Context, Result, anyhow};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::net::Ipv4Addr;
use wirepf_common::dto::{
    CreateIfaceBody, DnatMapping, ErrorResponse, Health, IfaceView, MasqueradeCfg, SnatMapping,
};

pub struct Client {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

impl Client {
    pub fn new(base: impl Into<String>, token: Option<String>) -> Result<Self> {
        let base = base.into().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .build()
            .context("build http client")?;
        Ok(Self { base, token, http })
    }

    pub async fn health(&self) -> Result<Health> {
        let resp = self.send(self.req(Method::GET, "/health", false)?).await?;
        decode_json(resp).await
    }

    pub async fn list_ifaces(&self) -> Result<Vec<IfaceView>> {
        let resp = self
            .send(self.req(Method::GET, "/interfaces", false)?)
            .await?;
        decode_json(resp).await
    }

    pub async fn create_iface(&self, name: &str) -> Result<IfaceView> {
        let body = CreateIfaceBody {
            name: name.to_string(),
        };
        let resp = self
            .send(self.req(Method::POST, "/interfaces", true)?.json(&body))
            .await?;
        decode_json(resp).await
    }

    pub async fn delete_iface(&self, name: &str) -> Result<()> {
        let path = format!("/interfaces/{}", urlencode(name));
        let resp = self.send(self.req(Method::DELETE, &path, true)?).await?;
        decode_empty(resp).await
    }

    pub async fn refresh_iface_ip(&self, name: &str) -> Result<IfaceView> {
        let path = format!("/interfaces/{}/refresh-ip", urlencode(name));
        let resp = self.send(self.req(Method::POST, &path, true)?).await?;
        decode_json(resp).await
    }

    pub async fn list_dnat(&self, iface: &str) -> Result<Vec<DnatMapping>> {
        let path = format!("/interfaces/{}/dnat", urlencode(iface));
        let resp = self.send(self.req(Method::GET, &path, false)?).await?;
        decode_json(resp).await
    }

    pub async fn add_dnat(
        &self,
        iface: &str,
        orig: Ipv4Addr,
        new: Ipv4Addr,
    ) -> Result<DnatMapping> {
        let path = format!("/interfaces/{}/dnat", urlencode(iface));
        let body = MappingBody { orig, new };
        let resp = self
            .send(self.req(Method::POST, &path, true)?.json(&body))
            .await?;
        decode_json(resp).await
    }

    pub async fn delete_dnat(&self, iface: &str, orig: Ipv4Addr) -> Result<()> {
        let path = format!("/interfaces/{}/dnat/{}", urlencode(iface), orig);
        let resp = self.send(self.req(Method::DELETE, &path, true)?).await?;
        decode_empty(resp).await
    }

    pub async fn list_snat(&self, iface: &str) -> Result<Vec<SnatMapping>> {
        let path = format!("/interfaces/{}/snat", urlencode(iface));
        let resp = self.send(self.req(Method::GET, &path, false)?).await?;
        decode_json(resp).await
    }

    pub async fn add_snat(
        &self,
        iface: &str,
        orig: Ipv4Addr,
        new: Ipv4Addr,
    ) -> Result<SnatMapping> {
        let path = format!("/interfaces/{}/snat", urlencode(iface));
        let body = MappingBody { orig, new };
        let resp = self
            .send(self.req(Method::POST, &path, true)?.json(&body))
            .await?;
        decode_json(resp).await
    }

    pub async fn delete_snat(&self, iface: &str, orig: Ipv4Addr) -> Result<()> {
        let path = format!("/interfaces/{}/snat/{}", urlencode(iface), orig);
        let resp = self.send(self.req(Method::DELETE, &path, true)?).await?;
        decode_empty(resp).await
    }

    pub async fn get_masquerade(&self, iface: &str) -> Result<MasqueradeCfg> {
        let path = format!("/interfaces/{}/masquerade", urlencode(iface));
        let resp = self.send(self.req(Method::GET, &path, false)?).await?;
        decode_json(resp).await
    }

    pub async fn put_masquerade(
        &self,
        iface: &str,
        cfg: &MasqueradeCfg,
    ) -> Result<MasqueradeCfg> {
        let path = format!("/interfaces/{}/masquerade", urlencode(iface));
        let resp = self
            .send(self.req(Method::PUT, &path, true)?.json(cfg))
            .await?;
        decode_json(resp).await
    }

    fn req(&self, method: Method, path: &str, mutating: bool) -> Result<RequestBuilder> {
        let url = format!("{}{}", self.base, path);
        let mut rb = self.http.request(method, &url);
        if mutating {
            let token = self
                .token
                .as_deref()
                .ok_or_else(|| anyhow!("--token / WIREPF_TOKEN required for this command"))?;
            rb = rb.bearer_auth(token);
        }
        Ok(rb)
    }

    async fn send(&self, rb: RequestBuilder) -> Result<Response> {
        rb.send().await.context("send request")
    }
}

#[derive(Serialize)]
struct MappingBody {
    orig: Ipv4Addr,
    new: Ipv4Addr,
}

async fn decode_json<T: DeserializeOwned>(resp: Response) -> Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.context("read response body")?;
    if !status.is_success() {
        return Err(api_error(status, &bytes).into());
    }
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "decode {} response: {}",
            status,
            String::from_utf8_lossy(&bytes)
        )
    })
}

async fn decode_empty(resp: Response) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let bytes = resp.bytes().await.unwrap_or_default();
    Err(api_error(status, &bytes).into())
}

fn api_error(status: StatusCode, bytes: &[u8]) -> ApiError {
    let message = serde_json::from_slice::<ErrorResponse>(bytes)
        .map(|e| e.error)
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned());
    ApiError { status, message }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
