#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use bpf_hole_common::{
    consts::PACKET_DATA_BUF_LEN,
    dns::{DNSHeader},
    loopback_addr_v4_as_be_u32, IpVersion,
};
use bpf_hole_xdp::ptr_at;
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
    let ethhdr: EthHdr = unsafe { *ptr_at(&ctx, 0)? };
    let version_str;
    let ip_hdr_enum: IpVersion = match ethhdr.ether_type {
        EtherType::Ipv4 => IpVersion::V4({
            version_str = "V4";
            unsafe { *ptr_at(&ctx, EthHdr::LEN).map_err(|_| ())? }
        }),
        EtherType::Ipv6 => IpVersion::V6({
            version_str = "V6";
            unsafe { *ptr_at(&ctx, EthHdr::LEN).map_err(|_| ())? }
        }),
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let udphdr: UdpHdr = match ip_hdr_enum.proto() {
        IpProto::Udp => unsafe { *ptr_at(&ctx, EthHdr::LEN + ip_hdr_enum.offset())? },
        _ => return Ok(XDP_PASS),
    };

    if udphdr.dest == 53u16.to_be() {
        info!(&ctx, "{} dropped on lo", version_str, udphdr.dest.to_le());
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
