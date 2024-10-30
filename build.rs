// build.rs
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the current directory
    let current_dir = env::current_dir()?;

    // Define the path for descriptor.bin in the current directory
    let descriptor_path = current_dir.join("descriptor.bin");

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
