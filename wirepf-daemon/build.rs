use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let dnat_ebpf_package = packages
        .iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wirepf-dnat-ebpf")
        .ok_or_else(|| anyhow!("wirepf-dnat-ebpf package not found"))?;

    let snat_ebpf_package = packages
        .iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "wirepf-snat-ebpf")
        .ok_or_else(|| anyhow!("wirepf-snat-ebpf package not found"))?;

    let dnat_ebpf_package = aya_build::Package {
        name: dnat_ebpf_package.name.as_str(),
        root_dir: dnat_ebpf_package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", dnat_ebpf_package.manifest_path))?
            .as_str(),
        ..Default::default()
    };

    let snat_ebpf_package = aya_build::Package {
        name: snat_ebpf_package.name.as_str(),
        root_dir: snat_ebpf_package
            .manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", snat_ebpf_package.manifest_path))?
            .as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf([dnat_ebpf_package, snat_ebpf_package], Toolchain::default())
}
