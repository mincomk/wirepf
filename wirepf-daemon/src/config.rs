use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub use wirepf_common::dto::{InterfaceCfg, Mapping};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/wirepf.json";
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:1204";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub bind_addr: Option<String>,
    #[serde(default)]
    pub interfaces: Vec<InterfaceCfg>,
}

impl Config {
    pub fn load_or_init(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let cfg: Config = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {}", path.display()))?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                cfg.save_atomic(path)
                    .with_context(|| format!("init {}", path.display()))?;
                Ok(cfg)
            }
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).ok();
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).context("serialize config")?;
        fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_BIND_ADDR)
    }

    pub fn find_iface(&self, name: &str) -> Option<&InterfaceCfg> {
        self.interfaces.iter().find(|i| i.name == name)
    }

    pub fn find_iface_mut(&mut self, name: &str) -> Option<&mut InterfaceCfg> {
        self.interfaces.iter_mut().find(|i| i.name == name)
    }
}
