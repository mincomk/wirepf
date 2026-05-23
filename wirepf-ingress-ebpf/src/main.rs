#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::HashMap,
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

// DNAT: original dst IP (network byte order) -> new dst IP.
#[map]
static DNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// SNAT: original src IP (network byte order) -> new src IP.
#[map]
static SNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn ingress(ctx: TcContext) -> i32 {
    match try_ingress(ctx) {
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

// Detect the IPv4 header offset within the packet.
//
// L2-less interfaces (wg, tun, ipip, etc.) deliver packets that start
// directly with the IPv4 header. Ethernet-like interfaces have a 14-byte
// L2 header.
//
// We bounds-check 14 bytes once (Ethernet-header size). Both candidate
// inspections — the ethertype at offset 12 and the IPv4 version+IHL byte
// at offset 0 — live inside that verified region. A single 1-byte bounds
// check would compile to `r4 >= r3`, which the kernel verifier does not
// recognise as widening the readable range.
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

fn try_ingress(ctx: TcContext) -> Result<i32, ()> {
    let Some(ip_off) = ipv4_offset(&ctx)? else {
        return Ok(TC_ACT_OK);
    };
    let ip: *mut Ipv4Hdr = ptr_at(&ctx, ip_off)?;

    let old_src = u32::from_ne_bytes(unsafe { (*ip).src_addr });
    let old_dst = u32::from_ne_bytes(unsafe { (*ip).dst_addr });
    let proto = unsafe { (*ip).proto() }.ok();

    // DNAT: rewrite dst if mapped.
    if let Some(&new_dst) = unsafe { DNAT_TABLE.get(&old_dst) } {
        rewrite_addr(&ctx, ip_off, old_dst, new_dst, proto, offset_of!(Ipv4Hdr, dst_addr))?;
    }

    // SNAT: rewrite src if mapped. Independent of DNAT — touches a different field.
    if let Some(&new_src) = unsafe { SNAT_TABLE.get(&old_src) } {
        rewrite_addr(&ctx, ip_off, old_src, new_src, proto, offset_of!(Ipv4Hdr, src_addr))?;
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
