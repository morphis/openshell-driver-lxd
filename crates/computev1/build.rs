// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("../../proto");
    let proto_file = proto_dir.join("compute_driver.proto");
    let include_dirs = [proto_dir.clone()];
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(std::slice::from_ref(&proto_file), &include_dirs)?;
    // compile_protos only names the entry point; the imports it pulls in are
    // generated too, so codegen has to re-run when any of them changes.
    for vendored in [
        "compute_driver.proto",
        "options.proto",
        "extension.proto",
        "sandbox.proto",
        "datamodel.proto",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            proto_dir.join(vendored).display()
        );
    }
    Ok(())
}
