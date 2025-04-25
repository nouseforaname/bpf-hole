#![no_std]
#![no_main]

use core::{mem::offset_of, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{
        __sk_buff, bpf_attach_type::BPF_TCX_INGRESS, BPF_F_INGRESS, BPF_F_PSEUDO_HDR,
        BPF_F_RECOMPUTE_CSUM, TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_REPEAT, TC_ACT_SHOT,
    },
    helpers::r#gen::bpf_redirect,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use bpf_hole_common::{
    consts::PACKET_DATA_BUF_LEN,
    dns::{decode_qname_data, DNSPacket},
    loopback_addr_as_be_u32,
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
#[map]
static BLOCKLIST: HashMap<[u8; PACKET_DATA_BUF_LEN], bool> = HashMap::with_max_entries(400000, 0);

#[classifier]
pub fn bpf_hole_tc(mut ctx: TcContext) -> i32 {
    match try_bpf_hole_tc(&mut ctx) {
        Ok(ret) => {
            debug!(&ctx, "success");
            ret
        }
        Err(_) => {
            info!(&ctx, "errored");
            TC_ACT_PIPE
        }
    }
}

fn try_bpf_hole_tc(ctx: &mut TcContext) -> Result<i32, ()> {
    let mut ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
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
        ctx,
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
    ctx.load_bytes(offset, &mut buf).map_err(|_| ())?;
    decode_qname_data(&mut buf);

    unsafe {
        let blocked = BLOCKLIST.get(&buf);
        let mut data = "";
        match buf.iter().position(|e| *e == 0b0) {
            Some(pos) => {
                //TODO: should the clamp use a 1 for lower bounds?
                data = str::from_utf8_unchecked(&buf[0..pos.clamp(0, PACKET_DATA_BUF_LEN)]);
            }
            _ => {}
        }
        match blocked {
            Some(_) => {
                // Is there a way to not time out and pretend that the connection was refused? Not sure if that would even be allowed in the context of traffic control eBPF but is it possible to rewrite the packet data? Send to a fake/local host?
                // https://docs.cilium.io/en/stable/reference-guides/bpf/progtypes/
                // according to tcpdumps this works and does in fact redirect. there is a response that can be seen by listening with `sudo tcpdump udp and host 127.0.0.1 -v`
                // network data is big endian. so these u32 which we deserialzed from network bytes are as well.
                let old_addr = ipv4hdr.dst_addr;
                ipv4hdr.dst_addr = loopback_addr_as_be_u32();

                info!(
                    ctx,
                    "updated ip: {:i}, to {:i} ",
                    old_addr.to_be(),
                    ipv4hdr.dst_addr()
                );
                ctx.store(EthHdr::LEN, &ipv4hdr, BPF_F_RECOMPUTE_CSUM as u64)
                    .map_err(|_| ())?;

                ctx.l3_csum_replace(
                    EthHdr::LEN + offset_of!(Ipv4Hdr, check),
                    old_addr as u64,
                    ipv4hdr.dst_addr as u64,
                    4,
                )
                .map_err(|_| ())?;

                debug!(ctx, "updated interface: {}", (*ctx.skb.skb).ifindex);

                // there are not many rust docs around bpf_redirect, but upstream libbpf has some. the signature seems to match
                // https://docs.ebpf.io/linux/helper-function/bpf_redirect/
                let _ = bpf_redirect(1, BPF_F_INGRESS as u64); // TODO: find out how to read ifindex for lo from  system. 1 == `lo` on my system.
                Ok(TC_ACT_REDIRECT)
            }
            _ => {
                debug!(ctx, "allowing: {} ", data);
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
