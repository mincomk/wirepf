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

    fn print_json<T: Serialize + ?Sized>(&self, v: &T) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(v)?);
        Ok(())
    }
}
