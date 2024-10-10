use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use crate::constants::{UNABLE_TO_GET_GROUP_NAME, UNABLE_TO_SET_GROUP_NAME};
use crate::group::Group;
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use tokio::fs;
use xdg::BaseDirectories;

mod backend;
mod common;
mod constants;
mod group;
mod repo;

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

    Ok(())
}
