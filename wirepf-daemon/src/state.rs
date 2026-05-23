use crate::bpf::AttachedIface;
use crate::config::Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Inner {
    pub config: Config,
    pub attached: HashMap<String, AttachedIface>,
}

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub inner: Arc<Mutex<Inner>>,
}

impl AppState {
    pub fn new(config_path: PathBuf, config: Config) -> Self {
        Self {
            config_path,
            inner: Arc::new(Mutex::new(Inner {
                config,
                attached: HashMap::new(),
            })),
        }
    }
}
