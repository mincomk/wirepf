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

// Un-DNAT table: private src IP (network byte order) -> original public src IP.
// Populated automatically as the mirror of each ingress DNAT entry.
#[map]
static UN_DNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// SNAT table: original src IP (network byte order) -> new src IP. Real 1:1 SNAT.
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

fn try_egress(ctx: TcContext) -> Result<i32, ()> {
    let eth: *mut EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*eth).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(TC_ACT_OK);
    }
    let ip: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    // Read packet fields we need *before* any mutating helper.
    let old_src = u32::from_ne_bytes(unsafe { (*ip).src_addr });
    let proto = unsafe { (*ip).proto() }.ok();

    // 1) Un-DNAT (return path of a DNAT'd flow).
    if let Some(&new_src) = unsafe { UN_DNAT_TABLE.get(&old_src) } {
        return rewrite_src(&ctx, old_src, new_src, proto).map(|_| TC_ACT_OK);
    }

    // 2) Real SNAT (configured 1:1 host IP -> host IP).
    if let Some(&new_src) = unsafe { SNAT_TABLE.get(&old_src) } {
        return rewrite_src(&ctx, old_src, new_src, proto).map(|_| TC_ACT_OK);
    }

    // 3) Masquerade (LPM-match on src against configured CIDRs; rewrite to iface IP).
    let enabled = MASQ_ENABLED.get(0).map(|v| *v).unwrap_or(0);
    if enabled != 0 {
        // old_src is the in-packet u32 (already in network-byte-order memory layout).
        // The LPM trie matches bits starting from byte 0 of `data`, which equals the
        // first dotted-quad octet, so we pass the value through unchanged.
        let key = Key::new(32, old_src);
        if unsafe { MASQ_CIDRS.get(&key) }.is_some() {
            let iface_ip = IFACE_IP.get(0).map(|v| *v).unwrap_or(0);
            if iface_ip != 0 {
                return rewrite_src(&ctx, old_src, iface_ip, proto).map(|_| TC_ACT_OK);
            }
        }
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn rewrite_src(
    ctx: &TcContext,
    old_src: u32,
    new_src: u32,
    proto: Option<IpProto>,
) -> Result<(), ()> {
    let l3_off = EthHdr::LEN + offset_of!(Ipv4Hdr, check);
    let src_off = EthHdr::LEN + offset_of!(Ipv4Hdr, src_addr);

    ctx.l3_csum_replace(l3_off, old_src as u64, new_src as u64, 4)
        .map_err(|_| ())?;

    match proto {
        Some(IpProto::Tcp) => {
            let l4_check_off = EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(TcpHdr, check);
            // 0x10 | 4 = BPF_F_PSEUDO_HDR | sizeof(src IP)
            ctx.l4_csum_replace(l4_check_off, old_src as u64, new_src as u64, 0x10 | 4)
                .map_err(|_| ())?;
        }
        Some(IpProto::Udp) => {
            let l4_check_off = EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check);
            // 0x10 | 0x20 | 4 = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(src IP)
            ctx.l4_csum_replace(
                l4_check_off,
                old_src as u64,
                new_src as u64,
                0x10 | 0x20 | 4,
            )
            .map_err(|_| ())?;
        }
        _ => {}
    }

    ctx.store(src_off, &new_src.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
