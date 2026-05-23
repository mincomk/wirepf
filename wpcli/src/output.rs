use crate::config::{Config, Context};
use anyhow::Result;
use comfy_table::{Cell, Table, presets::UTF8_FULL};
use serde::Serialize;
use wirepf_common::dto::{Health, IfaceView, Mapping};

pub struct Printer {
    json: bool,
}

impl Printer {
    pub fn new(json: bool) -> Self {
        Self { json }
    }

    pub fn health(&self, h: &Health) -> Result<()> {
        if self.json {
            return self.print_json(h);
        }
        println!("{}", if h.ok { "ok" } else { "unhealthy" });
        Ok(())
    }

    pub fn ifaces(&self, ifaces: &[IfaceView]) -> Result<()> {
        if self.json {
            return self.print_json(ifaces);
        }
        if ifaces.is_empty() {
            println!("(no interfaces)");
            return Ok(());
        }
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).set_header(vec!["NAME", "MAPPINGS"]);
        for i in ifaces {
            table.add_row(vec![Cell::new(&i.name), Cell::new(i.mappings.len())]);
        }
        println!("{table}");
        Ok(())
    }

    pub fn iface(&self, i: &IfaceView, action: &str) -> Result<()> {
        if self.json {
            return self.print_json(i);
        }
        println!("{action} interface {}", i.name);
        Ok(())
    }

    pub fn mappings(&self, mappings: &[Mapping]) -> Result<()> {
        if self.json {
            return self.print_json(mappings);
        }
        if mappings.is_empty() {
            println!("(no mappings)");
            return Ok(());
        }
        let mut table = Table::new();
        table.load_preset(UTF8_FULL).set_header(vec!["ORIG", "NEW"]);
        for m in mappings {
            table.add_row(vec![Cell::new(m.orig), Cell::new(m.new)]);
        }
        println!("{table}");
        Ok(())
    }

    pub fn mapping(&self, m: &Mapping, action: &str) -> Result<()> {
        if self.json {
            return self.print_json(m);
        }
        println!("{action} {} -> {}", m.orig, m.new);
        Ok(())
    }

    pub fn deleted(&self, kind: &str, id: &str) -> Result<()> {
        if self.json {
            return self.print_json(&serde_json::json!({
                "deleted": { "kind": kind, "id": id }
            }));
        }
        println!("deleted {kind} {id}");
        Ok(())
    }

    pub fn contexts(&self, cfg: &Config) -> Result<()> {
        if self.json {
            return self.print_json(cfg);
        }
        if cfg.contexts.is_empty() {
            println!("(no contexts)");
            return Ok(());
        }
        let current = cfg.current.as_deref().unwrap_or("");
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_header(vec!["", "NAME", "URL", "TOKEN"]);
        for (name, ctx) in &cfg.contexts {
            let star = if name == current { "*" } else { "" };
            let token = if ctx.token.is_some() { "***" } else { "-" };
            table.add_row(vec![
                Cell::new(star),
                Cell::new(name),
                Cell::new(&ctx.url),
                Cell::new(token),
            ]);
        }
        println!("{table}");
        Ok(())
    }

    pub fn context(&self, name: &str, ctx: &Context, current: bool) -> Result<()> {
        if self.json {
            return self.print_json(&serde_json::json!({
                "name": name,
                "current": current,
                "url": ctx.url,
                "token": ctx.token,
            }));
        }
        println!("name:    {name}{}", if current { " (current)" } else { "" });
        println!("url:     {}", ctx.url);
        println!(
            "token:   {}",
            if ctx.token.is_some() { "***" } else { "(none)" }
        );
        Ok(())
    }

    pub fn context_action(&self, action: &str, name: &str) -> Result<()> {
        if self.json {
            return self.print_json(&serde_json::json!({
                "context": { "action": action, "name": name }
            }));
        }
        println!("{action} context {name}");
        Ok(())
    }

    fn print_json<T: Serialize + ?Sized>(&self, v: &T) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(v)?);
        Ok(())
    }
}
