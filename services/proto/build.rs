use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("../../proto");

    let proto_files = [
        proto_dir.join("common.proto"),
        proto_dir.join("filter.proto"),
        proto_dir.join("backend.proto"),
        proto_dir.join("metrics.proto"),
        proto_dir.join("auth.proto"),
        proto_dir.join("worker.proto"),
    ];

    // Check that all proto files exist
    for proto_file in &proto_files {
        if !proto_file.exists() {
            panic!("Proto file not found: {:?}", proto_file);
        }
    }

    let out_dir = PathBuf::from("src/generated");
    std::fs::create_dir_all(&out_dir)?;

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        .compile_protos(
            &proto_files.iter().map(|p| p.to_str().unwrap()).collect::<Vec<_>>(),
            &[proto_dir.to_str().unwrap()],
        )?;

    // Tell cargo to rerun if protos change
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    Ok(())
}
