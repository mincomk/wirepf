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

// DNAT table: original dst IP (network byte order) -> new dst IP (network byte order)
#[map]
static DNAT_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

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

fn try_ingress(ctx: TcContext) -> Result<i32, ()> {
    let eth: *mut EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*eth).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(TC_ACT_OK);
    }
    let ip: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let old_dst = u32::from_ne_bytes(unsafe { (*ip).dst_addr });
    let proto = unsafe { (*ip).proto() };

    let new_dst = match unsafe { DNAT_TABLE.get(&old_dst) } {
        Some(&v) => v,

        // No mapping for this dst IP: leave packet alone. This is the common case, so avoid doing
        None => return Ok(TC_ACT_OK),
    };

    let l3_off = EthHdr::LEN + offset_of!(Ipv4Hdr, check);

    ctx.l3_csum_replace(l3_off, old_dst as u64, new_dst as u64, 4)
        .map_err(|_| ())?;

    match proto {
        Ok(IpProto::Tcp) => {
            let l4_check_off = EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(TcpHdr, check);
            ctx.l4_csum_replace(l4_check_off, old_dst as u64, new_dst as u64, 0x10 | 4)
                .map_err(|_| ())?;
        }
        Ok(IpProto::Udp) => {
            let l4_check_off = EthHdr::LEN + Ipv4Hdr::LEN + offset_of!(UdpHdr, check);
            ctx.l4_csum_replace(
                l4_check_off,
                old_dst as u64,
                new_dst as u64,
                0x10 | 0x20 | 4,
            )
            .map_err(|_| ())?;
        }
        _ => {}
    }

    let dst_off = EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr);
    ctx.store(dst_off, &new_dst.to_ne_bytes(), 0)
        .map_err(|_| ())?;

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
