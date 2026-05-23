mod cli;
mod client;
mod config;
mod output;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, IfaceCmd, MappingCmd};
use client::Client;
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
    let settings = config::resolve(cli.url, cli.token, cli.config)?;
    let client = Client::new(settings.url, settings.token)?;

    match cli.command {
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
