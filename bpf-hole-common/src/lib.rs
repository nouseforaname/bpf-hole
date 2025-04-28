#![no_std]
pub mod consts;
pub mod dns;

use network_types::ip::{in6_addr, in6_u, Ipv4Hdr, Ipv6Hdr};

pub enum IpVersion {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}

impl IpVersion {
    pub fn proto(&self) -> network_types::ip::IpProto {
        match self {
            Self::V4(hdr) => hdr.proto,
            Self::V6(hdr) => hdr.next_hdr,
        }
    }
    pub fn offset(&self) -> usize {
        match self {
            Self::V4(_) => Ipv4Hdr::LEN,
            Self::V6(_) => Ipv6Hdr::LEN,
        }
    }
}

pub fn loopback_addr_v4_as_be_u32() -> u32 {
    u32::from_be_bytes([127, 0, 0, 1])
}
pub fn loopback_addr_v6() -> in6_addr {
    network_types::ip::in6_addr {
        in6_u: in6_u {
            u6_addr32: [0u32, 0, 0, 1u32.to_be()],
        },
    }
}
pub fn ip_str_from_u32(value: u32, buf: &mut [u8; 16]) -> &str {
    let mut i = 0;
    let ascii_offset = 48; // 1 is 49
    [
        ((value >> 24) & 0xFF) as u8,
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
    .iter()
    .for_each(|&e| {
        let mut v = e / 100;
        if v > 0 {
            buf[i] = v + ascii_offset;
            i += 1;
        }
        v = e % 100 / 10;
        if v > 0 {
            buf[i] = v + ascii_offset;
            i += 1;
        }
        v = e % 100 % 10;
        buf[i] = v + ascii_offset;
        buf[i + 1] = 46;
        i += 2;
    });
    unsafe { core::str::from_utf8_unchecked(&buf[0..i - 2]) as &str }
}
