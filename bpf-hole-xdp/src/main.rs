#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::bpf_probe_read_kernel_buf,
    macros::xdp,
    programs::XdpContext,
};

use aya_log_ebpf::info;
use bpf_hole_common::{
    consts::PACKET_DATA_BUF_LEN,
    dns::{DNSAnswer, DNSHeader},
    IpVersion,
};
use bpf_hole_xdp::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::IpProto,
    udp::UdpHdr,
};

#[xdp]
pub fn bpf_hole_xdp(ctx: XdpContext) -> u32 {
    match try_bpf_hole(&ctx) {
        Ok(ret) => ret,
        Err(_) => {
            info!(&ctx, "error");
            xdp_action::XDP_ABORTED
        }
    }
}

fn try_bpf_hole(ctx: &XdpContext) -> Result<u32, ()> {
    let mut buf = [0u8; PACKET_DATA_BUF_LEN];
    let ethtype = unsafe { (*ptr_at::<EthHdr>(ctx, 0)?).ether_type };
    let ip_hdr_enum: IpVersion = match ethtype {
        EtherType::Ipv4 => IpVersion::V4(unsafe { *ptr_at(ctx, EthHdr::LEN).map_err(|_| ())? }),
        EtherType::Ipv6 => IpVersion::V6(unsafe { *ptr_at(ctx, EthHdr::LEN).map_err(|_| ())? }),
        _ => return Ok(xdp_action::XDP_PASS),
    };

    match ip_hdr_enum.proto() {
        IpProto::Udp => unsafe {
            if (*ptr_at::<UdpHdr>(ctx, EthHdr::LEN + ip_hdr_enum.offset())?).source != 53u16.to_be()
            {
                return Ok(XDP_PASS);
            }
        },
        _ => return Ok(XDP_PASS),
    };

    let payload_offset = EthHdr::LEN + ip_hdr_enum.offset() + UdpHdr::LEN + DNSHeader::HDRLEN;

    let dns_packet_data_ptr: *const _ = ptr_at(ctx, payload_offset)?;

    unsafe { bpf_probe_read_kernel_buf(dns_packet_data_ptr, &mut buf).map_err(|_| ())? };

    let answer_offset = get_answer_offset_from_payload(&mut buf) + payload_offset;

    let dns_answer_ptr: *const DNSAnswer = ptr_at(ctx, answer_offset)?;

    info!(ctx, "type: {}", unsafe { (*dns_answer_ptr).rtype() });
    info!(ctx, "class: {}", unsafe { (*dns_answer_ptr).class() });
    info!(ctx, "ttl: {}", unsafe { (*dns_answer_ptr).ttl() });
    info!(ctx, "data_len: {}", unsafe { (*dns_answer_ptr).data_len() });
    Ok(XDP_PASS)
    //let payload_len = ctx.data_end() - ctx.data();
    //info!(ctx,"packet len: {}", payload_len);

    //let answer= unsafe { (ptr_at::<DNSAnswer>(ctx, answer_offset)?).as_ref().ok_or(())? };

    //info!(ctx, "class: {}", unsafe {(*dns_answer_ptr).rtype.f1});
    //info!(ctx, "rtype: {}", (*dns_answer_ptr).rtype.to_be());
    //let data: &str = unsafe { core::str::from_utf8_unchecked(&buf[..answer_offset.clamp(1,buf.len()-1)]) };
    //let ttl= 5;
}

#[inline(always)]
pub fn get_answer_offset_from_payload(buf: &mut [u8]) -> usize {
    for i in 0..buf.len() - 10 {
        if buf[i] == 0xC0 {
            return i + 2;
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
