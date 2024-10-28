// build.rs
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the OUT_DIR from the environment
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Set the path for descriptor.bin to be inside OUT_DIR
    let descriptor_path = out_dir.join("descriptor.bin");

    // Configure tonic_build
    tonic_build::configure()
        .build_server(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["proto/rpc.proto"], &["proto"])?;

    // Print the path for debugging purposes
    println!(
        "cargo:warning=descriptor.bin generated at {}",
        descriptor_path.display()
    );

    Ok(())
}
