use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
};
use bpf_hole::read_blocklist_to_map;
use bpf_hole_common::consts::PACKET_DATA_BUF_LEN;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "xdp")]
    mode: String,
    #[clap(short, long, default_value = "./blocklist")]
    blocklist: String,
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
    let mut ebpf_xdp = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpf-hole-xdp-bin"
    )))?;
    let mut ebpf_tc = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpf-hole-tc-bin"
    )))?;
    let mut blocklist: HashMap<_, [u8; PACKET_DATA_BUF_LEN], u8>;
    match opt.mode.as_str() {
        "xdp" => {
            if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_xdp) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger xdp: {}", e);
            }
            let program_xdp: &mut Xdp = ebpf_xdp.program_mut("bpf_hole_xdp").unwrap().try_into()?;
            program_xdp.load()?;
            program_xdp
                .attach(&opt.iface, XdpFlags::default())
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

            blocklist = HashMap::try_from(ebpf_xdp.map_mut("BLOCKLIST").unwrap())?;
        }
        "tc" => {
            let _ = tc::qdisc_add_clsact(&opt.iface);

            if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_tc) {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger tc: {}", e);
            }
            let program_tc: &mut SchedClassifier =
                ebpf_tc.program_mut("bpf_hole_tc").unwrap().try_into()?;
            program_tc.load()?;
            program_tc
                .attach(&opt.iface, TcAttachType::Egress)
                .context("failed to attach the TC program with EGRESS Type")?;
            blocklist = HashMap::try_from(ebpf_tc.map_mut("BLOCKLIST").unwrap())?;
        }
        _ => {
            println!("Mode {} is not known.", opt.mode);
            return Ok(());
        }
    }

    println!("setting up blocklisted domain map");

    read_blocklist_to_map(&mut blocklist, &opt.blocklist)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
