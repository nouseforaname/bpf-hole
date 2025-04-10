use anyhow::Context as _;
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .filter(|cargo_metadata::Package { name, .. }| {
            println!("cargo:warning=name:{}", name);
            name == "bpf-hole-xdp" || name == "bpf-hole-tc"
        })
        .collect::<Vec<cargo_metadata::Package>>();
    assert_eq!(ebpf_package.iter().count(), 2);
    aya_build::build_ebpf(ebpf_package)
}
