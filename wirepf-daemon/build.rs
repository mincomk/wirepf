use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ingress_ebpf_package = packages
        .iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wirepf-ingress-ebpf")
        .ok_or_else(|| anyhow!("wirepf-ingress-ebpf package not found"))?;

    let egress_ebpf_package = packages
        .iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wirepf-egress-ebpf")
        .ok_or_else(|| anyhow!("wirepf-egress-ebpf package not found"))?;

    let ingress_ebpf_package = aya_build::Package {
        name: ingress_ebpf_package.name.as_str(),
        root_dir: ingress_ebpf_package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", ingress_ebpf_package.manifest_path))?
            .as_str(),
        ..Default::default()
    };

    let egress_ebpf_package = aya_build::Package {
        name: egress_ebpf_package.name.as_str(),
        root_dir: egress_ebpf_package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", egress_ebpf_package.manifest_path))?
            .as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf(
        [ingress_ebpf_package, egress_ebpf_package],
        Toolchain::default(),
    )
}
