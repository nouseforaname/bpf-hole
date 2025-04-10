#![no_std]

use core::mem;

use aya_ebpf::programs::XdpContext;
#[inline(always)] //
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
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
    return unsafe { core::str::from_utf8_unchecked(&buf[0..i - 2]) as &str };
}
