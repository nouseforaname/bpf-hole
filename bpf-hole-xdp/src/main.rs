#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, info};
use bpf_hole_common::{loopback_addr_as_be_u32, ptr_at};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[xdp]
pub fn bpf_hole_xdp(ctx: XdpContext) -> u32 {
    match try_bpf_hole(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_bpf_hole(ctx: XdpContext) -> Result<u32, ()> {
    debug!(&ctx, "enter xdp");
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let dst_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => return Ok(xdp_action::XDP_PASS),
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(()),
    };

    let dst_addr = u32::from(unsafe { (*ipv4hdr).dst_addr });

    if dst_addr == loopback_addr_as_be_u32() {
        info!(&ctx, "dropped on: {:i}:{}", dst_addr, dst_port);
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
