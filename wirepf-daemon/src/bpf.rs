use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf,
    maps::{Array, HashMap as BpfHashMap, LpmTrie, lpm_trie::Key},
    programs::{SchedClassifier, TcAttachType, tc},
};
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{AddressFamily, SockaddrLike};
use std::net::Ipv4Addr;
use wirepf_common::dto::{Cidr, DnatMapping, MasqueradeCfg, SnatMapping};

const INGRESS_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ingress"));
const EGRESS_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/egress"));

pub struct AttachedIface {
    pub ingress_bpf: Ebpf,
    pub egress_bpf: Ebpf,
    pub iface_ip: Option<Ipv4Addr>,
}

pub fn attach(iface: &str) -> Result<AttachedIface> {
    let mut ingress_bpf = Ebpf::load(INGRESS_BYTES).context("load ingress ebpf")?;
    let mut egress_bpf = Ebpf::load(EGRESS_BYTES).context("load egress ebpf")?;

    let _ = tc::qdisc_add_clsact(iface);

    let ingress_program: &mut SchedClassifier = ingress_bpf
        .program_mut("ingress")
        .ok_or_else(|| anyhow!("ingress program missing"))?
        .try_into()?;
    ingress_program.load().context("load ingress program")?;
    ingress_program
        .attach(iface, TcAttachType::Ingress)
        .inspect_err(|err| {
            eprintln!("failed to attach ingress program to {iface}: {err}");
        })
        .with_context(|| format!("attach ingress to {iface}"))?;

    let egress_program: &mut SchedClassifier = egress_bpf
        .program_mut("egress")
        .ok_or_else(|| anyhow!("egress program missing"))?
        .try_into()?;
    egress_program.load().context("load egress program")?;
    egress_program
        .attach(iface, TcAttachType::Egress)
        .inspect_err(|err| {
            eprintln!("failed to attach egress program to {iface}: {err}");
        })
        .with_context(|| format!("attach egress to {iface}"))?;

    let iface_ip = resolve_iface_ipv4(iface);
    let mut att = AttachedIface {
        ingress_bpf,
        egress_bpf,
        iface_ip,
    };
    write_iface_ip(&mut att, iface_ip)?;
    Ok(att)
}

pub fn insert_dnat(att: &mut AttachedIface, m: DnatMapping) -> Result<()> {
    let orig_be = u32::from(m.orig).to_be();
    let new_be = u32::from(m.new).to_be();

    dnat_table_mut(att)?.insert(orig_be, new_be, 0)?;
    un_dnat_table_mut(att)?.insert(new_be, orig_be, 0)?;
    Ok(())
}

pub fn remove_dnat(att: &mut AttachedIface, m: DnatMapping) -> Result<()> {
    let orig_be = u32::from(m.orig).to_be();
    let new_be = u32::from(m.new).to_be();

    let _ = dnat_table_mut(att)?.remove(&orig_be);
    let _ = un_dnat_table_mut(att)?.remove(&new_be);
    Ok(())
}

pub fn insert_snat(att: &mut AttachedIface, m: SnatMapping) -> Result<()> {
    let orig_be = u32::from(m.orig).to_be();
    let new_be = u32::from(m.new).to_be();

    snat_table_mut(att)?.insert(orig_be, new_be, 0)?;
    un_snat_table_mut(att)?.insert(new_be, orig_be, 0)?;
    Ok(())
}

pub fn remove_snat(att: &mut AttachedIface, m: SnatMapping) -> Result<()> {
    let orig_be = u32::from(m.orig).to_be();
    let new_be = u32::from(m.new).to_be();

    let _ = snat_table_mut(att)?.remove(&orig_be);
    let _ = un_snat_table_mut(att)?.remove(&new_be);
    Ok(())
}

pub fn set_masquerade(att: &mut AttachedIface, cfg: &MasqueradeCfg) -> Result<()> {
    rebuild_masq_cidrs(att, &cfg.src_cidrs)?;

    let effective = cfg.enabled && att.iface_ip.is_some();
    if cfg.enabled && att.iface_ip.is_none() {
        log::warn!("masquerade requested but interface IP unresolved; staying disabled");
    }
    write_masq_enabled(att, effective)?;
    Ok(())
}

pub fn refresh_iface_ip(att: &mut AttachedIface, iface: &str) -> Result<Option<Ipv4Addr>> {
    let ip = resolve_iface_ipv4(iface);
    att.iface_ip = ip;
    write_iface_ip(att, ip)?;
    Ok(ip)
}

fn resolve_iface_ipv4(iface: &str) -> Option<Ipv4Addr> {
    let iter = getifaddrs().ok()?;
    for ia in iter {
        if ia.interface_name != iface {
            continue;
        }
        let Some(addr) = ia.address else { continue };
        if addr.family() != Some(AddressFamily::Inet) {
            continue;
        }
        if let Some(sin) = addr.as_sockaddr_in() {
            return Some(sin.ip());
        }
    }
    None
}

fn dnat_table_mut(att: &mut AttachedIface) -> Result<BpfHashMap<&mut aya::maps::MapData, u32, u32>> {
    Ok(BpfHashMap::try_from(
        att.ingress_bpf
            .map_mut("DNAT_TABLE")
            .ok_or_else(|| anyhow!("DNAT_TABLE map missing"))?,
    )?)
}

fn un_dnat_table_mut(
    att: &mut AttachedIface,
) -> Result<BpfHashMap<&mut aya::maps::MapData, u32, u32>> {
    Ok(BpfHashMap::try_from(
        att.egress_bpf
            .map_mut("UN_DNAT_TABLE")
            .ok_or_else(|| anyhow!("UN_DNAT_TABLE map missing"))?,
    )?)
}

fn snat_table_mut(att: &mut AttachedIface) -> Result<BpfHashMap<&mut aya::maps::MapData, u32, u32>> {
    Ok(BpfHashMap::try_from(
        att.ingress_bpf
            .map_mut("SNAT_TABLE")
            .ok_or_else(|| anyhow!("SNAT_TABLE map missing"))?,
    )?)
}

fn un_snat_table_mut(
    att: &mut AttachedIface,
) -> Result<BpfHashMap<&mut aya::maps::MapData, u32, u32>> {
    Ok(BpfHashMap::try_from(
        att.egress_bpf
            .map_mut("UN_SNAT_TABLE")
            .ok_or_else(|| anyhow!("UN_SNAT_TABLE map missing"))?,
    )?)
}

fn rebuild_masq_cidrs(att: &mut AttachedIface, cidrs: &[Cidr]) -> Result<()> {
    let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(
        att.egress_bpf
            .map_mut("MASQ_CIDRS")
            .ok_or_else(|| anyhow!("MASQ_CIDRS map missing"))?,
    )?;

    let existing: Vec<Key<u32>> = trie
        .keys()
        .filter_map(|k| k.ok())
        .collect();
    for k in existing {
        let _ = trie.remove(&k);
    }

    for c in cidrs {
        if c.prefix_len > 32 {
            anyhow::bail!("invalid prefix_len {} for {}", c.prefix_len, c.addr);
        }
        let key = Key::new(c.prefix_len as u32, u32::from(c.addr).to_be());
        trie.insert(&key, 1u8, 0)?;
    }
    Ok(())
}

fn write_iface_ip(att: &mut AttachedIface, ip: Option<Ipv4Addr>) -> Result<()> {
    let mut arr: Array<_, u32> = Array::try_from(
        att.egress_bpf
            .map_mut("IFACE_IP")
            .ok_or_else(|| anyhow!("IFACE_IP map missing"))?,
    )?;
    let value = ip.map(|v| u32::from(v).to_be()).unwrap_or(0);
    arr.set(0, value, 0)?;
    Ok(())
}

fn write_masq_enabled(att: &mut AttachedIface, enabled: bool) -> Result<()> {
    let mut arr: Array<_, u32> = Array::try_from(
        att.egress_bpf
            .map_mut("MASQ_ENABLED")
            .ok_or_else(|| anyhow!("MASQ_ENABLED map missing"))?,
    )?;
    arr.set(0, if enabled { 1 } else { 0 }, 0)?;
    Ok(())
}
