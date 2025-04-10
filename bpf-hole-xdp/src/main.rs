#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use bpf_hole_common::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    //    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[xdp]
pub fn bpf_hole_xdp(ctx: XdpContext) -> u32 {
    match try_bpf_hole(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_bpf_hole(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let (src_port, dst_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => return Ok(xdp_action::XDP_PASS),
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(()),
    };

    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    // throw away everything that looks like a broadcast // multicast
    // 4294967295 == 255.255.255.255
    let mut octets_buf = [0u8; 16]; //initialize with whitespace => `32` == ` `

    if dst_port == 5353 || src_addr == 4294967295 || octets_buf[3] == 255 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_str = bpf_hole_common::ip_str_from_u32(dst_addr, &mut octets_buf);
    // do not care about multicast

    info!(&ctx, "parsed: '{}'", ip_str);

    info!(
        &ctx,
        "packet from: {:i}:{} -> {:i}:{}", src_addr, src_port, dst_addr, dst_port
    );

    Ok(xdp_action::XDP_PASS)
}
