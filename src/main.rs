use clap::{Command, Arg};
use anyhow::{Result, anyhow};
use xdg::BaseDirectories;
use tokio::fs;
use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use crate::group::Group;
use crate::repo::Repo;
use crate::constants::{UNABLE_TO_SET_GROUP_NAME, UNABLE_TO_GET_GROUP_NAME};

mod common;
mod group;
mod repo;
mod backend;
mod constants;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("Save DWeb Backend")
        .arg(Arg::new("pubkey")
            .long("pubkey")
            .value_name("PUBKEY")
            .help("Sets the public key for the group")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("secret")
            .long("seckey")
            .value_name("SECKEY")
            .help("Sets the secret key for the group")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("encryption_key")
            .long("enckey")
            .value_name("ENCKEY")
            .help("Sets the encryption key for the group")
            .value_parser(clap::value_parser!(String)))
        .get_matches();

    let path = xdg::BaseDirectories::with_prefix("save-dweb-backend")?.get_data_home();
    let port = 8080;

    fs::create_dir_all(&path).await.expect("Failed to create base directory");

    let mut backend = Backend::new(&path, port)?;

    backend.start().await?;

    // Check if keys were provided, otherwise create a new group
    if matches.contains_id("pubkey") && matches.contains_id("seckey") && matches.contains_id("enckey") {
        let pubkey = matches.get_one::<String>("pubkey").unwrap();
        let seckey = matches.get_one::<String>("seckey").unwrap();
        let enckey = matches.get_one::<String>("enckey").unwrap();
        println!("Provided Public Key: {:?}", pubkey);
        println!("Provided Secret Key: {:?}", seckey);
        println!("Provided Encryption Key: {:?}", enckey);
    } else {
        let group = backend.create_group().await?;
        println!("Group created with Public Key: {:?}", group.get_id());
        println!("Group created with Secret Key: {:?}", group.get_secret_key().unwrap());
        println!("Group created with Encryption Key: {:?}", group.get_encryption_key());
    }
    // Await for ctrl-c and then stop the backend
    tokio::signal::ctrl_c().await?;

    backend.stop().await?;

    Ok(())
}