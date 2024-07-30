use clap::{Command, Arg};
use eyre::Result;
use xdg::BaseDirectories;
use tokio::fs;
use crate::backend::Backend;
use crate::group::GroupKeypair;

mod group;
mod repo;
mod backend;

#[tokio::main]
async fn main() -> Result<()> {
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
        println!("Group created with Secret Key: {:?}", group.secret_key.as_ref().unwrap().value);
        println!("Group created with Encryption Key: {:?}", group.get_encryption_key());
    }

    tokio::signal::ctrl_c().await?;

    backend.stop().await?;

    Ok(())
}