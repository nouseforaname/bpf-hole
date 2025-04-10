use anyhow::Context as _;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev <iface> clsact'.

    let _ = tc::qdisc_add_clsact(&opt.iface);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf_xdp = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpf-hole-xdp-bin"
    )))?;
    let mut ebpf_tc = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpf-hole-tc-bin"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_tc) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger tc: {}", e);
    }
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_xdp) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger xdp: {}", e);
    }
    let Opt { iface } = opt;

    let program_xdp: &mut Xdp = ebpf_xdp.program_mut("bpf_hole_xdp").unwrap().try_into()?;
    program_xdp.load()?;
    program_xdp
        .attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let program_tc: &mut SchedClassifier =
        ebpf_tc.program_mut("bpf_hole_tc").unwrap().try_into()?;
    program_tc.load()?;
    program_tc
        .attach(&iface, TcAttachType::Egress)
        .context("failed to attach the TC program with EGRESS Type")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
