#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};

use aya_log_ebpf::{debug, info};
use bpf_hole_common::{consts::PACKET_DATA_BUF_LEN, dns::{decode_qname_data, DNSPacket}};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
#[map]
static BLOCKLIST: HashMap<[u8;PACKET_DATA_BUF_LEN], bool> = HashMap::with_max_entries(400000, 0);

#[classifier]
pub fn bpf_hole_tc(ctx: TcContext) -> i32 {
    match try_bpf_hole_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_bpf_hole_tc(ctx: TcContext) -> Result<i32, ()> {
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    match ipv4hdr.proto {
        network_types::ip::IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
            if u16::from_be(udphdr.dest) != 53 {
                return Ok(TC_ACT_PIPE);
            }
        }
        _ => {
            return Ok(TC_ACT_PIPE);
        }
    };
    let offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;

    let dns_packet: DNSPacket = ctx.load(offset).map_err(|_| ())?;
    debug!(
        &ctx,
        "ID: {}, QDCOUNT: {}, ANCOUNT: {}, {}, {}",
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
    let mut buf = [0u8; PACKET_DATA_BUF_LEN];
    ctx.load_bytes(offset, &mut buf).map_err(|_| {()})?;
    decode_qname_data(&mut buf);
    unsafe { let blocked = BLOCKLIST.get(&buf);
        let mut data = "";
        match buf.iter().position(|e| *e==0b0) {
            Some(pos) => {
                //TODO: should the clamp use a 1 for lower bounds?
                data = str::from_utf8_unchecked(&buf[0..pos.clamp(0,PACKET_DATA_BUF_LEN)]);
            }
            _ => {}
        }
        match blocked {
            Some(_) => {
                info!(&ctx, "dropping: {} ",data);
                // Is there a way to not time out and pretend that the connection was refused? Not sure if that would even be allowed in the context of traffic control eBPF but is it possible to rewrite the packet data? Send to a fake/local host?
                // REDIRECT seems to also make the request time out. at least on my client. but the docs also state that redirect will go to another or same device (whatever that means)
                // https://docs.cilium.io/en/stable/reference-guides/bpf/progtypes/
                Ok(TC_ACT_SHOT)
            }
            _ => {
                debug!(&ctx, "allowing: {} ",data);
                Ok(TC_ACT_PIPE)
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
