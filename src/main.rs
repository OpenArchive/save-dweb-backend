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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use tmpdir::TmpDir;

    #[tokio::test]
    async fn basic_test() {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();
        let port = 8080;

        fs::create_dir_all(path.as_ref()).await.expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref(), port).expect("Unable to create Backend");

        backend.start().await.expect("Unable to start");
        let group = backend.create_group().await.expect("Unable to create group");

        let group_key = group.get_id();
        group.set_name("Test Group").await.expect("Unable to set group name");
        let name = group.get_name().await.expect("Unable to get group name");
        assert_eq!(name, "Test Group");

        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");
        let loaded_group = backend.get_group(group_key.clone()).await.expect("Group not found");

        let protected_store = backend.get_protected_store().unwrap();
        let keypair_data = protected_store.load_user_secret(group_key.to_string()).await.expect("Failed to load keypair").expect("Keypair not found");
        let retrieved_keypair: GroupKeypair = serde_cbor::from_slice(&keypair_data).expect("Failed to deserialize keypair");

        assert_eq!(retrieved_keypair.public_key, group.get_id());
        assert_eq!(retrieved_keypair.secret_key, group.secret_key.as_ref().map(|sk| sk.value.clone()));
        assert_eq!(retrieved_keypair.encryption_key, group.get_encryption_key());

        assert_eq!(loaded_group.get_id(), retrieved_keypair.public_key);

        backend.stop().await.expect("Unable to stop");
    }
}
