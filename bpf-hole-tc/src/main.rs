#![no_std]
#![no_main]

use core::mem::offset_of;

use aya_ebpf::{
    bindings::{
        BPF_F_INGRESS, BPF_F_RECOMPUTE_CSUM, TC_ACT_OK, TC_ACT_PIPE, TC_ACT_REDIRECT, TC_ACT_SHOT,
    },
    helpers::r#gen::bpf_redirect,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{debug, info};
use bpf_hole_common::{
    consts::PACKET_DATA_BUF_LEN,
    dns::{decode_qname_data, DNSHeader},
    loopback_addr_v4_as_be_u32, loopback_addr_v6, IpVersion,
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};

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

const IFINDEX_LO: u32 = 1;

fn try_bpf_hole_tc(ctx: &mut TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    let ip_hdr_offset;
    let iphdr_version: IpVersion = match ethhdr.ether_type {
        network_types::eth::EtherType::Ipv4 => {
            debug!(ctx, "ipv4 detected");
            ip_hdr_offset = Ipv4Hdr::LEN;
            IpVersion::V4(ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| ())?)
        }
        network_types::eth::EtherType::Ipv6 => {
            debug!(ctx, "ipv6 detected");
            ip_hdr_offset = Ipv6Hdr::LEN;
            IpVersion::V6(ctx.load::<Ipv6Hdr>(EthHdr::LEN).map_err(|_| ())?)
        }
        _ => {
            return Ok(TC_ACT_PIPE);
        }
    };

    let udphdr: UdpHdr = match iphdr_version.proto() {
        network_types::ip::IpProto::Udp => ctx.load(EthHdr::LEN + ip_hdr_offset).map_err(|_| ())?,
        _ => return Ok(TC_ACT_PIPE),
    };

    debug!(ctx, "udp detected, checking port");
    if udphdr.dest != 53u16.to_be() {
        debug!(ctx, "traffic targets {}, allowing", udphdr.dest);
        return Ok(TC_ACT_PIPE);
    }

    let dns_packet: DNSHeader = ctx
        .load(EthHdr::LEN + ip_hdr_offset + UdpHdr::LEN)
        .map_err(|_| ())?;

    debug!(
        ctx,
        "ID: {}, QDCOUNT: {}, ANCOUNT: {}, {}, {}",
        dns_packet.ID.to_be(),
        dns_packet.QDCOUNT.to_be(),
        dns_packet.ANCOUNT.to_be(),
        dns_packet.NSCOUNT.to_be(),
        dns_packet.ARCOUNT.to_be()
    );

    let offset = EthHdr::LEN + iphdr_version.offset() + UdpHdr::LEN + DNSHeader::HDRLEN;
    let mut buf = [0u8; PACKET_DATA_BUF_LEN];

    // unfortunately aya will generate code that won't pass the verifier:
    // see: https://github.com/aya-rs/aya/pull/1218/files
    // the use of check_bounds_signed is patched locally
    // tried explicitly checking bounds here but failed.
    ctx.load_bytes(offset, &mut buf).map_err(|_| ())?;
    decode_qname_data(&mut buf);

    match unsafe { BLOCKLIST.get(&buf) } {
        Some(_) => {
            // according to tcpdumps this works and does in fact redirect.
            // there is a packet coming into `lo` that can be seen by listening with `sudo tcpdump udp and host 127.0.0.1 -v`.
            // The `-v` is important so it will print if something went wront with recalculating the checksums on the ip L3 header after changing the addr.
            match iphdr_version {
                IpVersion::V4(mut iphdr) => {
                    debug!(ctx, "v4 redirect");
                    let old_addr = iphdr.dst_addr;
                    iphdr.dst_addr = loopback_addr_v4_as_be_u32();
                    ctx.l3_csum_replace(
                        EthHdr::LEN + offset_of!(Ipv4Hdr, check),
                        old_addr as u64,
                        iphdr.dst_addr as u64,
                        4,
                    )
                    .map_err(|_| ())?;
                    ctx.store(EthHdr::LEN, &iphdr, BPF_F_RECOMPUTE_CSUM as u64)
                        .map_err(|_| ())?;
                }
                IpVersion::V6(mut iphdr) => {
                    debug!(ctx, "v6 redirect");
                    iphdr.dst_addr = loopback_addr_v6();
                    ctx.store(EthHdr::LEN, &iphdr, 0).map_err(|_| ())?;
                }
            }
        }
        _ => {
            return Ok(TC_ACT_PIPE);
        }
    };
    let ret = unsafe { bpf_redirect(IFINDEX_LO, BPF_F_INGRESS as u64) } as i32;

    match buf.iter().position(|e| *e == 0b0) {
        Some(pos) => {
            let data =
                unsafe { str::from_utf8_unchecked(&buf[0..pos.clamp(0, PACKET_DATA_BUF_LEN)]) };
            info!(ctx, "redirecting '{}'", data);
        }
        _ => {}
    }

    return Ok(ret);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
