mod api;
mod bpf;
mod config;
mod state;

use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::state::AppState;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Opt {
    #[clap(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let opt = Opt::parse();
    let cfg = Config::load_or_init(&opt.config)?;
    log::info!("loaded config from {}", opt.config.display());

    let state = AppState::new(opt.config.clone(), cfg);

    {
        let mut inner = state.inner.lock().await;
        let ifaces = inner.config.interfaces.clone();
        for iface in ifaces {
            match bpf::attach(&iface.name) {
                Ok(mut attached) => {
                    log::info!(
                        "attached ingress+egress on {} (iface_ip={:?})",
                        iface.name,
                        attached.iface_ip,
                    );
                    for m in &iface.dnat {
                        if let Err(e) = bpf::insert_dnat(&mut attached, *m) {
                            log::error!(
                                "failed to insert dnat {} -> {} on {}: {e}",
                                m.orig,
                                m.new,
                                iface.name
                            );
                        }
                    }
                    for m in &iface.snat {
                        if let Err(e) = bpf::insert_snat(&mut attached, *m) {
                            log::error!(
                                "failed to insert snat {} -> {} on {}: {e}",
                                m.orig,
                                m.new,
                                iface.name
                            );
                        }
                    }
                    if let Err(e) = bpf::set_masquerade(&mut attached, &iface.masquerade) {
                        log::error!("failed to set masquerade on {}: {e}", iface.name);
                    }
                    inner.attached.insert(iface.name.clone(), attached);
                }
                Err(e) => {
                    log::error!("failed to attach {}: {e}", iface.name);
                }
            }
        }
    }

    let bind_addr = {
        let inner = state.inner.lock().await;
        inner.config.bind_addr().to_string()
    };
    log::info!("REST API listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    let app = api::router(state);

    let server = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            log::error!("server error: {e}");
        }
    });

    tokio::signal::ctrl_c().await?;
    log::info!("shutting down");
    server.abort();
    Ok(())
}
