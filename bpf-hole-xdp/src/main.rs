#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::{bpf_probe_read_kernel_buf, r#gen::bpf_xdp_store_bytes},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use aya_log_ebpf::info;
use bpf_hole_common::{
    consts::PACKET_DATA_BUF_LEN,
    dns::{decode_qname_data, DNSAnswer, DNSHeader},
    IpVersion,
};
use bpf_hole_xdp::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::IpProto,
    udp::UdpHdr,
};

#[map]
static BLOCKLIST: HashMap<[u8; PACKET_DATA_BUF_LEN], bool> = HashMap::with_max_entries(400000, 0);

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

    decode_qname_data(&mut buf);

    match unsafe { BLOCKLIST.get(&buf) } {
        Some(_) => {
            unsafe { bpf_probe_read_kernel_buf(dns_packet_data_ptr, &mut buf).map_err(|_| ())? };
            let answer_offset = get_answer_offset_from_payload(&mut buf) + payload_offset;

            let dns_answer_ptr: *const DNSAnswer = ptr_at(ctx, answer_offset)?;

            info!(ctx, "type: {}", unsafe { (*dns_answer_ptr).rtype() });
            info!(ctx, "class: {}", unsafe { (*dns_answer_ptr).class() });
            info!(ctx, "ttl: {}", unsafe { (*dns_answer_ptr).ttl() });
            info!(ctx, "data_len: {}", unsafe { (*dns_answer_ptr).data_len() });
            let ip_addr_offset = answer_offset + size_of::<DNSAnswer>();
            match unsafe { (*dns_answer_ptr).rtype() } {
                // A record => v4 addr
                1 => {
                    info!(
                        ctx,
                        "first entry record => v4 replacing with {:i}",
                        0u32.to_be()
                    );
                    let ip_buf = [0u8; 4];
                    unsafe {
                        bpf_xdp_store_bytes(
                            ctx.ctx,
                            ip_addr_offset as u32,
                            ip_buf.as_ptr() as *mut _,
                            4,
                        )
                    };
                }
                // AAAA record => v6 addr
                28 => {
                    let ip_buf = [0u8; 16];
                    info!(ctx, "found AAAA record => v6 replacing with {:i}", ip_buf);
                    unsafe {
                        bpf_xdp_store_bytes(
                            ctx.ctx,
                            ip_addr_offset as u32,
                            ip_buf.as_ptr() as *mut _,
                            16,
                        )
                    };
                }
                // don't fiddle with anything else for now
                _ => {}
            }
        }
        None => return Ok(XDP_PASS),
    }

    Ok(XDP_PASS)
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
