mod cli;
mod client;
mod config;
mod output;

use anyhow::{Result, bail};
use clap::Parser;
use cli::{Cli, Command, ContextCmd, DnatCmd, IfaceCmd, MasqueradeCmd, SnatCmd};
use client::Client;
use config::{Config, Context};
use output::Printer;
use wirepf_common::dto::{Cidr, MasqueradeCfg};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let printer = Printer::new(cli.json);
    if let Err(e) = run(cli, &printer).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli, printer: &Printer) -> Result<()> {
    if let Command::Context(cmd) = cli.command {
        return run_context(cmd, cli.context, cli.config, printer);
    }

    let cfg = config::load(cli.config.clone())?;
    let settings = config::resolve(&cfg, cli.url, cli.token, cli.context)?;
    let client = Client::new(settings.url, settings.token)?;

    match cli.command {
        Command::Context(_) => unreachable!(),
        Command::Health => printer.health(&client.health().await?),
        Command::Iface(IfaceCmd::List) => printer.ifaces(&client.list_ifaces().await?),
        Command::Iface(IfaceCmd::Create { name }) => {
            printer.iface(&client.create_iface(&name).await?, "created")
        }
        Command::Iface(IfaceCmd::Delete { name }) => {
            client.delete_iface(&name).await?;
            printer.deleted("interface", &name)
        }
        Command::Iface(IfaceCmd::RefreshIp { name }) => {
            printer.iface(&client.refresh_iface_ip(&name).await?, "refreshed")
        }
        Command::Dnat(DnatCmd::List { iface }) => {
            printer.dnat_list(&client.list_dnat(&iface).await?)
        }
        Command::Dnat(DnatCmd::Add { iface, orig, new }) => {
            printer.dnat(&client.add_dnat(&iface, orig, new).await?, "mapped")
        }
        Command::Dnat(DnatCmd::Delete { iface, orig }) => {
            client.delete_dnat(&iface, orig).await?;
            printer.deleted("dnat", &format!("{iface}/{orig}"))
        }
        Command::Snat(SnatCmd::List { iface }) => {
            printer.snat_list(&client.list_snat(&iface).await?)
        }
        Command::Snat(SnatCmd::Add { iface, orig, new }) => {
            printer.snat(&client.add_snat(&iface, orig, new).await?, "mapped")
        }
        Command::Snat(SnatCmd::Delete { iface, orig }) => {
            client.delete_snat(&iface, orig).await?;
            printer.deleted("snat", &format!("{iface}/{orig}"))
        }
        Command::Masquerade(MasqueradeCmd::Show { iface }) => {
            printer.masquerade(&client.get_masquerade(&iface).await?)
        }
        Command::Masquerade(MasqueradeCmd::Set {
            iface,
            enabled,
            cidrs,
        }) => {
            let current = client.get_masquerade(&iface).await?;
            let cfg = MasqueradeCfg {
                enabled: enabled.unwrap_or(current.enabled),
                src_cidrs: if cidrs.is_empty() {
                    current.src_cidrs
                } else {
                    cidrs
                        .into_iter()
                        .map(|(addr, prefix_len)| Cidr { addr, prefix_len })
                        .collect()
                },
            };
            printer.masquerade(&client.put_masquerade(&iface, &cfg).await?)
        }
        Command::Masquerade(MasqueradeCmd::Clear { iface }) => {
            let cfg = MasqueradeCfg::default();
            printer.masquerade(&client.put_masquerade(&iface, &cfg).await?)
        }
    }
}

fn run_context(
    cmd: ContextCmd,
    cli_context: Option<String>,
    config_path: Option<std::path::PathBuf>,
    printer: &Printer,
) -> Result<()> {
    let mut cfg = config::load(config_path.clone())?;
    match cmd {
        ContextCmd::List => printer.contexts(&cfg),
        ContextCmd::Show { name } => {
            let name = resolve_show_name(&cfg, name, cli_context)?;
            let ctx = cfg
                .contexts
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("context `{name}` not found"))?;
            let is_current = cfg.current.as_deref() == Some(name.as_str());
            printer.context(&name, ctx, is_current)
        }
        ContextCmd::Add { name, url, token } => {
            if cfg.contexts.contains_key(&name) {
                bail!("context `{name}` already exists");
            }
            let token = match token.as_deref() {
                Some("-") => Some(config::read_token_from_stdin()?),
                Some(_) => token,
                None => None,
            };
            cfg.contexts.insert(name.clone(), Context { url, token });
            if cfg.current.is_none() {
                cfg.current = Some(name.clone());
            }
            config::save(&cfg, config_path)?;
            printer.context_action("added", &name)
        }
        ContextCmd::Delete { name } => {
            if !cfg.contexts.contains_key(&name) {
                bail!("context `{name}` not found");
            }
            if cfg.current.as_deref() == Some(name.as_str()) {
                bail!(
                    "cannot delete current context `{name}`; switch with `wpcli context use <other>` first"
                );
            }
            cfg.contexts.remove(&name);
            config::save(&cfg, config_path)?;
            printer.context_action("deleted", &name)
        }
        ContextCmd::Use { name } => {
            if !cfg.contexts.contains_key(&name) {
                bail!("context `{name}` not found");
            }
            cfg.current = Some(name.clone());
            config::save(&cfg, config_path)?;
            printer.context_action("switched to", &name)
        }
        ContextCmd::Rename { old, new } => {
            if old == new {
                return printer.context_action("renamed", &new);
            }
            let ctx = cfg
                .contexts
                .remove(&old)
                .ok_or_else(|| anyhow::anyhow!("context `{old}` not found"))?;
            if cfg.contexts.contains_key(&new) {
                cfg.contexts.insert(old.clone(), ctx);
                bail!("context `{new}` already exists");
            }
            cfg.contexts.insert(new.clone(), ctx);
            if cfg.current.as_deref() == Some(old.as_str()) {
                cfg.current = Some(new.clone());
            }
            config::save(&cfg, config_path)?;
            printer.context_action("renamed", &format!("{old} -> {new}"))
        }
    }
}

fn resolve_show_name(
    cfg: &Config,
    arg_name: Option<String>,
    cli_context: Option<String>,
) -> Result<String> {
    if let Some(n) = arg_name {
        return Ok(n);
    }
    if let Some(n) = cli_context {
        return Ok(n);
    }
    if let Ok(n) = std::env::var("WIREPF_CONTEXT")
        && !n.is_empty()
    {
        return Ok(n);
    }
    cfg.current.clone().ok_or_else(|| {
        anyhow::anyhow!("no current context; pass a name or run `wpcli context use <name>`")
    })
}
