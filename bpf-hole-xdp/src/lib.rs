#![no_std]

#[inline(always)] //
pub fn ptr_at<T>(ctx: &aya_ebpf::programs::XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
