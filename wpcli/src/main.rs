mod cli;
mod client;
mod config;
mod output;

use anyhow::{Result, bail};
use clap::Parser;
use cli::{Cli, Command, ContextCmd, IfaceCmd, MappingCmd};
use client::Client;
use config::{Config, Context};
use output::Printer;

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
        Command::Mapping(MappingCmd::List { iface }) => {
            printer.mappings(&client.list_mappings(&iface).await?)
        }
        Command::Mapping(MappingCmd::Add { iface, orig, new }) => {
            printer.mapping(&client.add_mapping(&iface, orig, new).await?, "mapped")
        }
        Command::Mapping(MappingCmd::Delete { iface, orig }) => {
            client.delete_mapping(&iface, orig).await?;
            printer.deleted("mapping", &format!("{iface}/{orig}"))
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
    cfg.current
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no current context; pass a name or run `wpcli context use <name>`"))
}
