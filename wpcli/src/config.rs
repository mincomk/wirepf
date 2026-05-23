use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_URL: &str = "http://127.0.0.1:1204";

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    url: Option<String>,
    token: Option<String>,
}

#[derive(Debug)]
pub struct Settings {
    pub url: String,
    pub token: Option<String>,
}

pub fn resolve(
    flag_url: Option<String>,
    flag_token: Option<String>,
    flag_config: Option<PathBuf>,
) -> Result<Settings> {
    let file = load_file(flag_config)?;
    let url = flag_url
        .or(file.url)
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    let token = flag_token.or(file.token);
    Ok(Settings { url, token })
}

fn load_file(explicit: Option<PathBuf>) -> Result<FileConfig> {
    let path = match explicit {
        Some(p) => Some(p),
        None => default_config_path(),
    };
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    read_file(&path)
}

fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("wpcli").join("config.toml"))
}

fn read_file(path: &Path) -> Result<FileConfig> {
    match fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}
