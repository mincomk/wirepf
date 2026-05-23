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
    Dnat(DnatCmd),
    #[command(subcommand)]
    Snat(SnatCmd),
    #[command(subcommand)]
    Masquerade(MasqueradeCmd),
    #[command(subcommand)]
    Context(ContextCmd),
}

#[derive(Subcommand, Debug)]
pub enum IfaceCmd {
    List,
    Create { name: String },
    Delete { name: String },
    RefreshIp { name: String },
}

#[derive(Subcommand, Debug)]
pub enum DnatCmd {
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
pub enum SnatCmd {
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
pub enum MasqueradeCmd {
    Show {
        iface: String,
    },
    Set {
        iface: String,
        #[arg(long, value_parser = parse_bool)]
        enabled: Option<bool>,
        #[arg(long = "cidr", value_parser = parse_cidr)]
        cidrs: Vec<(Ipv4Addr, u8)>,
    },
    Clear {
        iface: String,
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

fn parse_bool(s: &str) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "no" | "n" | "0" | "off" => Ok(false),
        _ => Err(format!("expected true/false, got `{s}`")),
    }
}

fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("expected a.b.c.d/n, got `{s}`"))?;
    let addr: Ipv4Addr = addr.parse().map_err(|e| format!("bad address: {e}"))?;
    let prefix: u8 = prefix.parse().map_err(|e| format!("bad prefix: {e}"))?;
    if prefix > 32 {
        return Err(format!("prefix {prefix} > 32"));
    }
    Ok((addr, prefix))
}
