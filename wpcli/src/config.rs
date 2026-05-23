use anyhow::{Context as _, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const DEFAULT_URL: &str = "http://127.0.0.1:1204";
const ENV_URL: &str = "WIREPF_URL";
const ENV_TOKEN: &str = "WIREPF_TOKEN";
const ENV_CONTEXT: &str = "WIREPF_CONTEXT";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub current: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, Context>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token: Option<String>,
}

#[derive(Debug)]
pub struct Settings {
    pub url: String,
    pub token: Option<String>,
}

pub fn config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    dirs::config_dir()
        .map(|d| d.join("wpcli").join("config.toml"))
        .ok_or_else(|| anyhow!("could not determine user config directory"))
}

pub fn load(explicit: Option<PathBuf>) -> Result<Config> {
    let path = config_path(explicit)?;
    load_from(&path)
}

fn load_from(path: &Path) -> Result<Config> {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let value: toml::Value =
        toml::from_str(&s).with_context(|| format!("parse {}", path.display()))?;
    let table = value
        .as_table()
        .ok_or_else(|| anyhow!("{}: expected table at root", path.display()))?;
    if table.contains_key("url") || table.contains_key("token") {
        bail!(
            "{}: config schema has changed; top-level `url`/`token` is no longer supported. \
             Run: wpcli context add default --url <url> --token <token> && wpcli context use default",
            path.display()
        );
    }
    toml::Value::Table(table.clone())
        .try_into()
        .with_context(|| format!("parse {}", path.display()))
}

pub fn save(cfg: &Config, explicit: Option<PathBuf>) -> Result<()> {
    let path = config_path(explicit)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(cfg).context("serialize config")?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn resolve(
    cfg: &Config,
    flag_url: Option<String>,
    flag_token: Option<String>,
    flag_context: Option<String>,
) -> Result<Settings> {
    let env_context = env::var(ENV_CONTEXT).ok().filter(|s| !s.is_empty());
    let env_url = env::var(ENV_URL).ok().filter(|s| !s.is_empty());
    let env_token = env::var(ENV_TOKEN).ok().filter(|s| !s.is_empty());

    let selected: Option<&Context> = match flag_context.as_deref().or(env_context.as_deref()) {
        Some(name) => Some(
            cfg.contexts
                .get(name)
                .ok_or_else(|| anyhow!("context `{name}` not found"))?,
        ),
        None => cfg
            .current
            .as_deref()
            .map(|name| {
                cfg.contexts
                    .get(name)
                    .ok_or_else(|| anyhow!("current context `{name}` not found"))
            })
            .transpose()?,
    };

    let url = flag_url
        .or_else(|| selected.map(|c| c.url.clone()))
        .or(env_url)
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    let token = flag_token
        .or_else(|| selected.and_then(|c| c.token.clone()))
        .or(env_token);
    Ok(Settings { url, token })
}

pub fn read_token_from_stdin() -> Result<String> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).context("read token from stdin")?;
    let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
    if trimmed.is_empty() {
        bail!("empty token from stdin");
    }
    Ok(trimmed)
}

