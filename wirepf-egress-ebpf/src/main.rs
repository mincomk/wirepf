#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{Array, HashMap, LpmTrie, lpm_trie::Key},
    programs::TcContext,
};
use core::mem;
use core::mem::offset_of;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Un-DNAT: private src IP (network byte order) -> original public src IP.
// Populated automatically as the mirror of each ingress DNAT entry.
#[map]
static UN_DNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// SNAT: original src IP (network byte order) -> new src IP. Real 1:1 SNAT.
#[map]
static SNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Masquerade source-CIDR set. Key is (prefix_len, addr_be). Value is presence marker (1).
#[map]
static MASQ_CIDRS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

// Single-entry array holding the egress interface's primary IPv4 (network byte order).
// Userspace writes this at attach + on refresh.
#[map]
static IFACE_IP: Array<u32> = Array::with_max_entries(1, 0);

// Single-entry array: 0 = masquerade disabled, non-zero = enabled.
#[map]
static MASQ_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    match try_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

// Detect the IPv4 header offset within the packet. See ingress for rationale.
#[inline(always)]
fn ipv4_offset(ctx: &TcContext) -> Result<Option<usize>, ()> {
    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*eth).ether_type() } == Ok(EtherType::Ipv4) {
        return Ok(Some(EthHdr::LEN));
    }
    let first_byte = unsafe { *(eth as *const u8) };
    if (first_byte >> 4) == 4 {
        Ok(Some(0))
    } else {
        Ok(None)
    }
}

fn try_egress(ctx: TcContext) -> Result<i32, ()> {
    let Some(ip_off) = ipv4_offset(&ctx)? else {
        return Ok(TC_ACT_OK);
    };
    let ip: *mut Ipv4Hdr = ptr_at(&ctx, ip_off)?;

    let old_src = u32::from_ne_bytes(unsafe { (*ip).src_addr });
    let proto = unsafe { (*ip).proto() }.ok();

    // src rewrites are mutually exclusive — first match wins.
    //
    //   1) un-DNAT: return path of an ingress DNAT (most specific, paired with a DNAT entry).
    //   2) SNAT:    configured 1:1 source rewrite.
    //   3) MASQ:    LPM-match against configured source CIDRs; rewrite to the iface IP.
    if let Some(&new_src) = unsafe { UN_DNAT_TABLE.get(&old_src) } {
        return rewrite_addr(
            &ctx,
            ip_off,
            old_src,
            new_src,
            proto,
            offset_of!(Ipv4Hdr, src_addr),
        )
        .map(|_| TC_ACT_OK);
    }

    if let Some(&new_src) = unsafe { SNAT_TABLE.get(&old_src) } {
        return rewrite_addr(
            &ctx,
            ip_off,
            old_src,
            new_src,
            proto,
            offset_of!(Ipv4Hdr, src_addr),
        )
        .map(|_| TC_ACT_OK);
    }

    let enabled = MASQ_ENABLED.get(0).map(|v| *v).unwrap_or(0);
    if enabled != 0 {
        // old_src is the in-packet u32 (network-byte-order memory layout).
        let key = Key::new(32, old_src);
        if unsafe { MASQ_CIDRS.get(&key) }.is_some() {
            let iface_ip = IFACE_IP.get(0).map(|v| *v).unwrap_or(0);
            if iface_ip != 0 {
                return rewrite_addr(
                    &ctx,
                    ip_off,
                    old_src,
                    iface_ip,
                    proto,
                    offset_of!(Ipv4Hdr, src_addr),
                )
                .map(|_| TC_ACT_OK);
            }
        }
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn rewrite_addr(
    ctx: &TcContext,
    ip_off: usize,
    old: u32,
    new: u32,
    proto: Option<IpProto>,
    addr_off_in_ip: usize,
) -> Result<(), ()> {
    let l3_off = ip_off + offset_of!(Ipv4Hdr, check);
    let addr_off = ip_off + addr_off_in_ip;

    ctx.l3_csum_replace(l3_off, old as u64, new as u64, 4)
        .map_err(|_| ())?;

    match proto {
        Some(IpProto::Tcp) => {
            let l4_check_off = ip_off + Ipv4Hdr::LEN + offset_of!(TcpHdr, check);
            // 0x10 | 4 = BPF_F_PSEUDO_HDR | sizeof(IPv4 addr)
            ctx.l4_csum_replace(l4_check_off, old as u64, new as u64, 0x10 | 4)
                .map_err(|_| ())?;
        }
        Some(IpProto::Udp) => {
            let l4_check_off = ip_off + Ipv4Hdr::LEN + offset_of!(UdpHdr, check);
            // 0x10 | 0x20 | 4 = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(IPv4 addr)
            ctx.l4_csum_replace(l4_check_off, old as u64, new as u64, 0x10 | 0x20 | 4)
                .map_err(|_| ())?;
        }
        _ => {}
    }

    ctx.store(addr_off, &new.to_ne_bytes(), 0).map_err(|_| ())?;
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
