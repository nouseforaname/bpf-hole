#![no_std]
#![no_main]


use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},macros::{classifier, map}, maps::HashMap, programs::TcContext
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr}, udp::UdpHdr,
};

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
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be(ipv4hdr.dst_addr);

    let (_, dst_port) = match ipv4hdr.proto {
        IpProto::Tcp => return Ok(TC_ACT_PIPE),
        IpProto::Udp => {
            let udphdr: UdpHdr = ctx.load(EthHdr::LEN +Ipv4Hdr::LEN).map_err(|_| ())?;
          (
              u16::from_be(udphdr.source ),
              u16::from_be(udphdr.dest ),
           )
        }
        _ => {
          return Ok(TC_ACT_PIPE);
        },
    };

    if dst_port != 53 {
        return Ok(TC_ACT_PIPE);
    }
    let dns_header_len=12; // 96 bits for header data
    let mut buf = [0; 256];

    info!(&ctx, "DNS Query to parsed: '{:i}:{}'", destination, dst_port);
    let data_len= ctx.len();
    let offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN ;
    info!(&ctx, "data_len: {}, offset: {} ", data_len,offset);
    // unfortunately aya will generate code that won't pass the verifier:
    // see: https://github.com/aya-rs/aya/pull/1218/files
    // the use of check_bounds_signed is patched locally
    // tried explicitly checking bounds here but failed.
    ctx.load_bytes(offset + dns_header_len, &mut buf).map_err(|_| ())?;
    let data = unsafe { core::str::from_utf8_unchecked(&buf) };
    info!(&ctx, "data: {}", data);
  //}
    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
