use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "wpcli", about = "Command-line client for the wirepf daemon")]
pub struct Cli {
    #[arg(long, env = "WIREPF_URL", global = true)]
    pub url: Option<String>,

    #[arg(long, env = "WIREPF_TOKEN", global = true, hide_env_values = true)]
    pub token: Option<String>,

    #[arg(long, env = "WIREPF_CONTEXT", global = true)]
    pub context: Option<String>,

    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Health,
    #[command(subcommand)]
    Iface(IfaceCmd),
    #[command(subcommand)]
    Mapping(MappingCmd),
    #[command(subcommand)]
    Context(ContextCmd),
}

#[derive(Subcommand, Debug)]
pub enum IfaceCmd {
    List,
    Create { name: String },
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum MappingCmd {
    List {
        iface: String,
    },
    Add {
        iface: String,
        orig: Ipv4Addr,
        new: Ipv4Addr,
    },
    Delete {
        iface: String,
        orig: Ipv4Addr,
    },
}

#[derive(Subcommand, Debug)]
pub enum ContextCmd {
    List,
    Show {
        name: Option<String>,
    },
    Add {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long, hide_env_values = true)]
        token: Option<String>,
    },
    Delete {
        name: String,
    },
    Use {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
}
