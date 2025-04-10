#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
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

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
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
    let octets_src: [u8; 4] = [
        ((src_addr >> 24) & 0xFF) as u8,
        ((src_addr >> 16) & 0xFF) as u8,
        ((src_addr >> 8) & 0xFF) as u8,
        (src_addr & 0xFF) as u8,
    ];
    //let octets_dst: [u8; 4] = [
    //    ((dst_addr >> 24) & 0xFF) as u8,
    //    ((dst_addr >> 16) & 0xFF) as u8,
    //    ((dst_addr >> 8) & 0xFF) as u8,
    //    (dst_addr & 0xFF) as u8,
    //];

    // do not care about multicast
    if dst_port == 5353 || src_addr == 4294967295 || octets_src[3] == 255 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ascii_offset = 48;
    let mut ip_bytes = [0u8; 16];
    let mut i = 0;
    for mut octet in octets_src {
        'inner: for _ in 0..3 {
            let d = octet % 10;
            octet = octet / 10;
            ip_bytes[i] = d + ascii_offset;
            i += 1;
            if octet == 0 {
                break 'inner;
            }
        }
        ip_bytes[i] = 46;
    }
    unsafe {
        let ip_str = core::str::from_utf8_unchecked(&ip_bytes);
        info!(&ctx, "parsed: {}", ip_str);
    };

    info!(
        &ctx,
        "packet from: {:i}:{} -> {:i}:{}", src_addr, src_port, dst_addr, dst_port
    );

    Ok(xdp_action::XDP_PASS)
}
