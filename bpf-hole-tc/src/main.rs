#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},macros::{classifier, map}, maps::{HashMap, PerCpuArray}, programs::TcContext
};
use aya_log_ebpf::info;
use bpf_hole_common::dns::DNSPacket;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr, udp::UdpHdr,
};
const BUF_LEN:usize= 128;
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn bpf_hole_tc(ctx: TcContext) -> i32 {
    match try_bpf_hole_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_bpf_hole_tc(ctx: TcContext) -> Result<i32, ()> {

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let dst_port = match ipv4hdr.proto {
        network_types::ip::IpProto::Tcp => return Ok(TC_ACT_PIPE),
        network_types::ip::IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN +Ipv4Hdr::LEN).map_err(|_| ())?;
            u16::from_be(udphdr.dest)
        }
        _ => {
          return Ok(TC_ACT_PIPE);
        },
    };

    if dst_port != 53 {
        return Ok(TC_ACT_PIPE);
    }

    let offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
    let dns_packet:DNSPacket = ctx.load(offset).map_err(|_| ())?;
    info!(&ctx, "ID: {}, QDCOUNT: {}, ANCOUNT: {}, {}, {}",
        dns_packet.ID.to_be(),
        dns_packet.QDCOUNT.to_be(),
        dns_packet.ANCOUNT.to_be(),
        dns_packet.NSCOUNT.to_be(),
        dns_packet.ARCOUNT.to_be()
    );

    // unfortunately aya will generate code that won't pass the verifier:
    // see: https://github.com/aya-rs/aya/pull/1218/files
    // the use of check_bounds_signed is patched locally
    // tried explicitly checking bounds here but failed.

    let offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DNSPacket::HDRLEN;
    let mut buf = [0u8;BUF_LEN];
    ctx.load_bytes(offset, &mut buf).map_err(|_| {
        info!(&ctx, "load bytes error");
        ()
    })?;
    let mut bytes_until_segment_ends = buf[0];
    let mut str_len=0;
    for e in buf[1..].iter_mut(){
        str_len += 1;
        if bytes_until_segment_ends > 0 {
            bytes_until_segment_ends -=1;
            continue;
        }
        // the TLD . (after the TLD) marks the end of the hostname. QNAME uses an empty octet -> 0b00
        if *e == 0 {
            break;
        }
        bytes_until_segment_ends = *e;
        *e = 46;
    }
    let data: &str = unsafe { str::from_utf8_unchecked(&buf[1..str_len.min(BUF_LEN)])};
    info!(&ctx, "data: {} ,max index: {}",data,  str_len);

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
