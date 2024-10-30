use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use crate::constants::{UNABLE_TO_GET_GROUP_NAME, UNABLE_TO_SET_GROUP_NAME};
use crate::group::Group;
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::{Arg, Command, ArgAction};
use tokio::fs;
use tokio::task;
use tokio::sync::Mutex;
use std::sync::Arc;
use xdg::BaseDirectories;
use tracing::error;

mod backend;
mod common;
mod constants;
mod group;
mod repo;
mod rpc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("Save DWeb Backend")
        .arg(
            Arg::new("pubkey")
                .long("pubkey")
                .value_name("PUBKEY")
                .help("Sets the public key for the group")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("secret")
                .long("seckey")
                .value_name("SECKEY")
                .help("Sets the secret key for the group")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("rpc")
                .long("rpc")
                .help("Starts the RPC backup server")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rpc_addr")
                .long("rpc-addr")
                .value_name("RPC_ADDR")
                .help("Sets the address for the RPC server")
                .default_value("127.0.0.1:50051")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("encryption_key")
                .long("enckey")
                .value_name("ENCKEY")
                .help("Sets the encryption key for the group")
                .value_parser(clap::value_parser!(String)),
        )
        .get_matches();

    let xdg_dirs = BaseDirectories::with_prefix("save-dweb-backend")?;
    let base_dir = xdg_dirs.get_data_home();

    fs::create_dir_all(&base_dir)
        .await
        .expect("Failed to create base directory");

    let mut backend = Backend::new(&base_dir)?;

    if matches.get_flag("rpc") {
        // If --rpc is passed, start the RPC server only
        let rpc_addr = matches.get_one::<String>("rpc_addr").unwrap();
        println!("Starting RPC server on {}", rpc_addr);

        // Start the backend to initialize necessary components
        backend.start().await?;

        // Start the RPC server with the backend
        rpc::start_rpc_server(backend.clone(), rpc_addr).await?;

    } else {
        // Otherwise, start the normal backend and group operations
        backend.start().await?;

        // Check if keys were provided, otherwise create a new group
        if matches.contains_id("pubkey")
            && matches.contains_id("seckey")
            && matches.contains_id("enckey")
        {
            let pubkey = matches.get_one::<String>("pubkey").unwrap();
            let seckey = matches.get_one::<String>("seckey").unwrap();
            let enckey = matches.get_one::<String>("enckey").unwrap();
            println!("Provided Public Key: {:?}", pubkey);
            println!("Provided Secret Key: {:?}", seckey);
            println!("Provided Encryption Key: {:?}", enckey);
        } else {
            let group = backend.create_group().await?;
            println!("Group created with Record Key: {:?}", group.id());
            println!(
                "Group created with Secret Key: {:?}",
                group.get_secret_key().unwrap()
            );
            println!(
                "Group created with Encryption Key: {:?}",
                group.get_encryption_key()
            );
        }

        // Await for ctrl-c and then stop the backend
        tokio::signal::ctrl_c().await?;
        backend.stop().await?;
    }

    Ok(())
}
