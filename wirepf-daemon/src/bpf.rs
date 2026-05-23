use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf,
    maps::HashMap as BpfHashMap,
    programs::{SchedClassifier, TcAttachType},
};
use std::net::Ipv4Addr;

const DNAT_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/dnat"));
const SNAT_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snat"));

pub struct AttachedIface {
    pub dnat_bpf: Ebpf,
    pub snat_bpf: Ebpf,
}

pub fn attach(iface: &str) -> Result<AttachedIface> {
    let mut dnat_bpf = Ebpf::load(DNAT_BYTES).context("load dnat ebpf")?;
    let mut snat_bpf = Ebpf::load(SNAT_BYTES).context("load snat ebpf")?;

    let dnat_program: &mut SchedClassifier = dnat_bpf
        .program_mut("dnat")
        .ok_or_else(|| anyhow!("dnat program missing"))?
        .try_into()?;
    dnat_program.load().context("load dnat program")?;
    dnat_program
        .attach(iface, TcAttachType::Ingress)
        .with_context(|| format!("attach dnat to {iface}"))?;

    let snat_program: &mut SchedClassifier = snat_bpf
        .program_mut("snat")
        .ok_or_else(|| anyhow!("snat program missing"))?
        .try_into()?;
    snat_program.load().context("load snat program")?;
    snat_program
        .attach(iface, TcAttachType::Egress)
        .with_context(|| format!("attach snat to {iface}"))?;

    Ok(AttachedIface { dnat_bpf, snat_bpf })
}

pub fn insert_mapping(att: &mut AttachedIface, orig: Ipv4Addr, new: Ipv4Addr) -> Result<()> {
    let orig_be = u32::from(orig).to_be();
    let new_be = u32::from(new).to_be();

    let mut dnat: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        att.dnat_bpf
            .map_mut("DNAT_TABLE")
            .ok_or_else(|| anyhow!("DNAT_TABLE map missing"))?,
    )?;
    dnat.insert(orig_be, new_be, 0)?;

    let mut snat: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        att.snat_bpf
            .map_mut("SNAT_TABLE")
            .ok_or_else(|| anyhow!("SNAT_TABLE map missing"))?,
    )?;
    snat.insert(new_be, orig_be, 0)?;

    Ok(())
}

pub fn remove_mapping(att: &mut AttachedIface, orig: Ipv4Addr, new: Ipv4Addr) -> Result<()> {
    let orig_be = u32::from(orig).to_be();
    let new_be = u32::from(new).to_be();

    let mut dnat: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        att.dnat_bpf
            .map_mut("DNAT_TABLE")
            .ok_or_else(|| anyhow!("DNAT_TABLE map missing"))?,
    )?;
    let _ = dnat.remove(&orig_be);

    let mut snat: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        att.snat_bpf
            .map_mut("SNAT_TABLE")
            .ok_or_else(|| anyhow!("SNAT_TABLE map missing"))?,
    )?;
    let _ = snat.remove(&new_be);

    Ok(())
}
