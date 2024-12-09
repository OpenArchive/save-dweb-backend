pub mod backend;
pub mod common;
pub mod constants;
pub mod group;
pub mod repo;
pub mod rpc;

use crate::constants::{
    FAILED_TO_DESERIALIZE_KEYPAIR, FAILED_TO_LOAD_KEYPAIR, GROUP_NOT_FOUND, KEYPAIR_NOT_FOUND,
    ROUTE_ID_DHT_KEY, TEST_GROUP_NAME, UNABLE_TO_GET_GROUP_NAME, UNABLE_TO_SET_GROUP_NAME,
    UNABLE_TO_STORE_KEYPAIR,
};

use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};

use iroh_blobs::Hash;
use veilid_core::{
    vld0_generate_keypair, CryptoKey, CryptoTyped, TypedKey, VeilidUpdate, CRYPTO_KIND_VLD0,
    VALID_CRYPTO_KINDS,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

use serial_test::serial;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use anyhow::Result;
    use bytes::Bytes;
    use common::init_veilid;
    use rpc::RpcClient;
    use rpc::RpcService;
    use std::path::Path;
    use std::result;
    use tmpdir::TmpDir;
    use tokio::fs;
    use tokio::join;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use tokio::time::Duration;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::StreamExt;

    #[tokio::test]
    #[serial]
    async fn blob_transfer() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Create a group and a repo
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        let repo = group.create_repo().await.expect("Unable to create repo");

        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        // Prepare data to upload as a blob
        let data_to_upload = b"Test data for blob".to_vec();
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(data_to_upload.clone())))
            .await
            .unwrap();
        drop(tx); // Close the sender

        // upload the data as a blob and get the hash
        let hash = iroh_blobs
            .upload_from_stream(rx)
            .await
            .expect("Failed to upload blob");

        // some delay to ensure blob is uploaded
        tokio::time::sleep(Duration::from_millis(100)).await;

        // download the blob
        let receiver = iroh_blobs
            .read_file(hash.clone())
            .await
            .expect("Failed to read blob");

        // retrieve the data from the receiver
        let mut retrieved_data = Vec::new();
        let mut stream = ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {:?}", e),
            }
        }

        // Verify that the downloaded data matches the uploaded data
        assert_eq!(retrieved_data, data_to_upload);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn group_creation() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);
        let name = group.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(name, TEST_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn keypair_storage_and_retrieval() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");

        let mut loaded_group = backend.get_group(&group.id()).await.expect(GROUP_NOT_FOUND);

        let protected_store = backend.get_protected_store().await.unwrap();
        let keypair_data = protected_store
            .load_user_secret(group.id().to_string())
            .await
            .expect(FAILED_TO_LOAD_KEYPAIR)
            .expect(KEYPAIR_NOT_FOUND);

        let retrieved_keypair: CommonKeypair =
            serde_cbor::from_slice(&keypair_data).expect(FAILED_TO_DESERIALIZE_KEYPAIR);

        // Check that the id matches group.id()
        assert_eq!(retrieved_keypair.id, group.id());

        // Check that the public_key matches the owner public key from the DHT record
        assert_eq!(
            retrieved_keypair.public_key,
            loaded_group.get_dht_record().owner().clone()
        );

        // Check that the secret and encryption keys match
        assert_eq!(retrieved_keypair.secret_key, group.get_secret_key());
        assert_eq!(retrieved_keypair.encryption_key, group.get_encryption_key());

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn repo_creation() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Step 1: Create a group before creating a repo
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Step 2: Create a repo
        let repo = group.create_repo().await.expect("Unable to create repo");

        let repo_key = repo.get_id();
        assert!(repo_key != CryptoKey::default(), "Repo ID should be set");

        // Step 3: Set and verify the repo name
        let repo_name = "Test Repo";

        repo.set_name(repo_name)
            .await
            .expect("Unable to set repo name");

        let name = repo.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);

        assert_eq!(name, repo_name);

        // Step 5: List known repos and verify the repo is in the list
        let repos = group.list_repos().await;
        assert!(repos.contains(&repo_key));

        // Step 6: Retrieve the repo by key and check its name
        let loaded_repo = group.get_repo(&repo_key).await.expect("Repo not found");

        let retrieved_name = loaded_repo
            .get_name()
            .await
            .expect("Unable to get repo name after restart");
        assert_eq!(retrieved_name, repo_name);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn sending_message_via_private_route() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(888), async {
            let path = TmpDir::new("test_dweb_backend").await.unwrap();

            fs::create_dir_all(path.as_ref())
                .await
                .expect("Failed to create base directory");

            let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
            backend.start().await.expect("Unable to start");

            // Add delay to ensure backend initialization
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Create a group and a repo
            let mut group = backend
                .create_group()
                .await
                .expect("Unable to create group");
            let repo = group.create_repo().await.expect("Unable to create repo");
            let veilid_api = backend
                .get_veilid_api()
                .await
                .expect("Failed to get VeilidAPI instance");

            // Get the update receiver from the backend
            let update_rx = backend
                .subscribe_updates()
                .await
                .expect("Failed to subscribe to updates");

            // Set up a channel to receive AppMessage updates
            let (message_tx, mut message_rx) = mpsc::channel(1);

            // Spawn a task to listen for updates
            tokio::spawn(async move {
                let mut rx = update_rx.resubscribe();
                while let Ok(update) = rx.recv().await {
                    if let VeilidUpdate::AppMessage(app_message) = update {
                        // Optionally, filter by route_id or other criteria
                        message_tx.send(app_message).await.unwrap();
                    }
                }
            });

            println!(
                "Creating a new custom private route with valid crypto kinds: {:?}",
                VALID_CRYPTO_KINDS
            );

            // Create a new private route
            let (route_id, route_id_blob) = veilid_api
                .new_custom_private_route(
                    &VALID_CRYPTO_KINDS,
                    veilid_core::Stability::Reliable,
                    veilid_core::Sequencing::PreferOrdered,
                )
                .await
                .expect("Failed to create route");

            // Store the route_id_blob in DHT
            repo.store_route_id_in_dht(route_id_blob.clone())
                .await
                .expect("Failed to store route ID blob in DHT");

            // Define the message to send
            let message = b"Test Message to Repo Owner".to_vec();

            println!("Sending message to owner...");

            // Send the message
            repo.send_message_to_owner(&veilid_api, message.clone(), ROUTE_ID_DHT_KEY)
                .await
                .expect("Failed to send message to repo owner");

            // Receive the message from the background task
            let received_app_message = message_rx.recv().await.expect("Failed to receive message");

            // Verify the message
            assert_eq!(received_app_message.message(), message.as_slice());

            backend.stop().await.expect("Unable to stop");
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn known_group_persistence() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);

        drop(group);

        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");

        let list = backend.list_groups().await?;

        assert_eq!(list.len(), 1, "Group auto-loaded on start");

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn group_name_persistence() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");
        let loaded_group = backend.get_group(&group.id()).await.expect(GROUP_NOT_FOUND);

        let name = loaded_group
            .get_name()
            .await
            .expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(name, TEST_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }
    #[tokio::test]
    #[serial]
    async fn repo_persistence() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start backend");

        let mut group = backend
            .create_group()
            .await
            .expect("Failed to create group");
        let group_id = group.id();

        // Drop the group and stop the backend
        drop(group);
        backend.stop().await.expect("Unable to stop backend");

        // Restart backend and verify group and repo persistence
        backend.start().await.expect("Unable to restart backend");
        println!(
            "Backend restarted, attempting to load group with ID: {:?}",
            group_id
        );

        let mut reload_group = backend.get_group(&group_id).await.expect(GROUP_NOT_FOUND);
        let loaded_group_id = reload_group.id();

        // Drop the group and stop the backend
        drop(reload_group);
        backend.stop().await.expect("Unable to stop backend");

        // Restart backend and verify group and repo persistence
        backend.start().await.expect("Unable to restart backend");
        println!(
            "Backend restarted, attempting to load group with ID: {:?}",
            loaded_group_id
        );

        let mut loaded_group = backend
            .get_group(&loaded_group_id)
            .await
            .expect(GROUP_NOT_FOUND);
        println!("group reloaded with id: {:?}", loaded_group_id);
        let repo = loaded_group
            .create_repo()
            .await
            .expect("Unable to create repo");

        let repo_name = "Test Repo";
        repo.set_name(repo_name)
            .await
            .expect("Unable to set repo name");

        let initial_name = repo.get_name().await.expect("Unable to get repo name");
        assert_eq!(initial_name, repo_name, "Initial repo name doesn't match");

        let repo_id = repo.id();
        println!("lib: Repo created with id: {:?}", repo_id);

        // Check if the repo is listed after restart
        let list = loaded_group.list_repos().await;
        assert_eq!(list.len(), 1, "One repo got loaded back");

        let loaded_repo = loaded_group
            .get_own_repo()
            .await
            .expect("Repo not found after restart");

        println!("a list of repos: {:?}", list);

        let retrieved_name = loaded_repo
            .get_name()
            .await
            .expect("Unable to get repo name after restart");
        assert_eq!(
            retrieved_name, repo_name,
            "Repo name doesn't persist after restart"
        );

        // Drop the group again and test reloading
        drop(loaded_group);
        backend
            .stop()
            .await
            .expect("Unable to stop backend after second drop");

        backend
            .start()
            .await
            .expect("Unable to restart backend after second drop");

        // Verify the group and repos again
        let reloaded_group = backend.get_group(&group_id).await.expect(GROUP_NOT_FOUND);
        let reloaded_repos = reloaded_group.list_repos().await;
        assert_eq!(
            reloaded_repos.len(),
            1,
            "One repo loaded after second restart"
        );

        let another_list = reloaded_group.list_repos().await;

        println!("Another list of repos: {:?}", another_list);

        let reloaded_repo = reloaded_group
            .get_own_repo()
            .await
            .expect("Repo not found after second restart");

        let final_name = reloaded_repo
            .get_name()
            .await
            .expect("Unable to get repo name after second restart");
        assert_eq!(
            final_name, repo_name,
            "Repo name doesn't persist after second restart"
        );

        let known = backend.list_known_group_ids().await?;
        assert_eq!(known.len(), 1, "One group got saved");

        backend
            .stop()
            .await
            .expect("Unable to stop backend after verification");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn upload_blob_test() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend_upload_blob").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Create a group
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Prepare a temporary file to upload as a blob
        let tmp_file_path = path.as_ref().join("test_blob_file.txt");
        let file_content = b"Test content for file upload";
        fs::write(&tmp_file_path, file_content)
            .await
            .expect("Failed to write to temp file");

        let repo = group.create_repo().await?;

        // Upload the file as a blob and get the hash
        let hash = repo
            .upload_blob(tmp_file_path.clone())
            .await
            .expect("Failed to upload blob");

        // Verify that the file was uploaded and the hash was written to the DHT
        let dht_value = backend
            .get_veilid_api()
            .await
            .expect("veilid_api not initialized")
            .routing_context()
            .expect("Failed to get routing context")
            .get_dht_value(repo.dht_record.key().clone(), 1, false)
            .await
            .expect("Failed to retrieve DHT value");

        if let Some(dht_value_data) = dht_value {
            // Use the data() method to extract the byte slice
            let dht_value_bytes = dht_value_data.data();
            let dht_value_str = String::from_utf8(dht_value_bytes.to_vec())
                .expect("Failed to convert ValueData to String");
            assert_eq!(dht_value_str, hash.to_hex());
        } else {
            panic!("No value found in DHT for the given key");
        }

        // Read back the file using the hash
        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");
        let receiver = iroh_blobs
            .read_file(hash.clone())
            .await
            .expect("Failed to read blob");

        // Retrieve the data from the receiver
        let mut retrieved_data = Vec::new();
        let mut stream = ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {:?}", e),
            }
        }

        // Verify that the downloaded data matches the original file content
        assert_eq!(retrieved_data, file_content);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }
    #[tokio::test]
    #[serial]
    async fn upload_blob_and_verify_protected_store() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend_upload_blob").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Create a group
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Prepare a temporary file to upload as a blob
        let tmp_file_path = path.as_ref().join("test_blob_file.txt");
        let file_content = b"Test content for file upload";
        fs::write(&tmp_file_path, file_content)
            .await
            .expect("Failed to write to temp file");

        let protected_store = backend.get_protected_store().await.unwrap();

        let repo = group.create_repo().await?;

        // Upload the file as a blob and get the hash
        let hash = repo
            .upload_blob(tmp_file_path.clone())
            .await
            .expect("Failed to upload blob");

        // Verify that the file was uploaded and the hash was written to the DHT
        let dht_value = backend
            .get_veilid_api()
            .await
            .expect("veilid_api not initialized")
            .routing_context()
            .expect("Failed to get routing context")
            .get_dht_value(repo.dht_record.key().clone(), 1, false)
            .await
            .expect("Failed to retrieve DHT value");

        if let Some(dht_value_data) = dht_value {
            // Use the data() method to extract the byte slice
            let dht_value_bytes = dht_value_data.data();
            let dht_value_str = String::from_utf8(dht_value_bytes.to_vec())
                .expect("Failed to convert ValueData to String");
            assert_eq!(dht_value_str, hash.to_hex());
        } else {
            panic!("No value found in DHT for the given key");
        }

        // Read back the file using the hash
        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        let receiver = iroh_blobs
            .read_file(hash.clone())
            .await
            .expect("Failed to read blob");

        // Retrieve the data from the receiver
        let mut retrieved_data = Vec::new();
        let mut stream = ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {:?}", e),
            }
        }

        // Verify that the downloaded data matches the original file content
        assert_eq!(retrieved_data, file_content);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_join() {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");

        backend.start().await.expect("Unable to start");
        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);

        let url = group.get_url();

        let keys = backend::parse_url(url.as_str()).expect("URL was parsed back out");

        assert_eq!(keys.id, group.id());
        backend.stop().await.expect("Unable to stop");
    }

    #[tokio::test]
    #[serial]
    async fn list_repos_test() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend_list_repos").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Create a group and two repos
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        let repo1 = group.create_repo().await?.clone();

        // List repos and verify
        let repos = group.list_repos().await;
        assert!(repos.contains(&repo1.get_id()));

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn get_own_repo_test() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend_get_own_repo").await.unwrap();

        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Create a group and two repos, one writable
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        let writable_repo = group.create_repo().await?.clone();

        // Verify own repo is found
        let own_repo = group.get_own_repo().await;
        assert!(own_repo.is_some());
        assert_eq!(own_repo.unwrap().get_id(), writable_repo.get_id());

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn download_hash_from_peers_test() -> Result<()> {
        let base_dir = TmpDir::new("test_dweb_backend_download_hash")
            .await
            .unwrap();

        let base_dir_path = base_dir.to_path_buf();

        let store1 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh1")).await?;
        let store2 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh2")).await?;

        let (v1_result, v2_result) = join!(
            init_veilid(&base_dir_path, "downloadpeers1".to_string()),
            init_veilid(&base_dir_path, "downloadpeers2".to_string())
        );
        let (veilid_api1, mut update_rx1) = v1_result?;
        let (veilid_api2, mut update_rx2) = v2_result?;

        fs::create_dir_all(base_dir.as_ref())
            .await
            .expect("Failed to create base directory");

        let backend1 = Backend::from_dependencies(
            &base_dir.to_path_buf(),
            veilid_api1.clone(),
            update_rx1,
            store1,
        )
        .await
        .unwrap();

        let backend2 = Backend::from_dependencies(
            &base_dir.to_path_buf(),
            veilid_api2.clone(),
            update_rx2,
            store2,
        )
        .await
        .unwrap();

        // Create a group and a peer repo
        let mut group = backend1
            .create_group()
            .await
            .expect("Unable to create group");

        let mut peer_repo = group.create_repo().await?;

        sleep(Duration::from_secs(1)).await;

        let group2 = backend2.join_from_url(&group.get_url()).await?;

        // Upload a test blob to the peer repo
        let data_to_upload = Bytes::from("Test data for peer download");
        let collection_name = "peer_repo_collection".to_string();
        peer_repo
            .iroh_blobs
            .create_collection(&collection_name)
            .await
            .expect("Unable to create collection");

        // Create a file stream using mpsc
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok(data_to_upload.clone())).await.unwrap();
        drop(tx); // Close the sender

        // Upload using the new method `upload_to`
        let file_path = "test_file.txt".to_string();
        let file_hash = peer_repo
            .iroh_blobs
            .upload_to(&collection_name, &file_path, rx)
            .await
            .expect("Failed to upload to collection");

        // Add the uploaded file to the collection
        let new_file_collection_hash = peer_repo
            .iroh_blobs
            .set_file(&collection_name, &file_path, &file_hash)
            .await
            .expect("Unable to add file to collection");
        assert!(
            !new_file_collection_hash.as_bytes().is_empty(),
            "New collection hash after uploading a file should not be empty"
        );

        sleep(Duration::from_secs(1)).await;

        // Download hash from peers
        group2.download_hash_from_peers(&file_hash).await?;

        backend1.stop().await?;
        backend2.stop().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn peers_have_hash_test() -> Result<()> {
        let base_dir: TmpDir = TmpDir::new("test_dweb_backend_peers_have_hash")
            .await
            .unwrap();

        let base_dir_path = base_dir.to_path_buf();

        let store1 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh1")).await?;
        let store2 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh2")).await?;

        let (v1_result, v2_result) = join!(
            init_veilid(&base_dir_path, "downloadpeers1".to_string()),
            init_veilid(&base_dir_path, "downloadpeers2".to_string())
        );
        let (veilid_api1, mut update_rx1) = v1_result?;
        let (veilid_api2, mut update_rx2) = v2_result?;

        fs::create_dir_all(base_dir.as_ref())
            .await
            .expect("Failed to create base directory");

        let backend1 = Backend::from_dependencies(
            &base_dir.to_path_buf(),
            veilid_api1.clone(),
            update_rx1,
            store1,
        )
        .await
        .unwrap();

        let backend2 = Backend::from_dependencies(
            &base_dir.to_path_buf(),
            veilid_api2.clone(),
            update_rx2,
            store2,
        )
        .await
        .unwrap();

        // Create a group and a peer repo
        let mut group1 = backend1
            .create_group()
            .await
            .expect("Unable to create group");

        let mut peer_repo = group1.create_repo().await?;

        // Upload a test blob to the peer repo
        let data_to_upload = Bytes::from("Test data for peer check");
        let collection_name = "peer_repo_collection_check".to_string();
        peer_repo
            .iroh_blobs
            .create_collection(&collection_name)
            .await
            .expect("Unable to create collection");

        // Create a file stream using mpsc
        let (tx, rx) = mpsc::channel(1);
        tx.send(Ok(data_to_upload.clone())).await.unwrap();
        drop(tx); // Close the sender

        let iroh_blobs = backend1
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        // Upload using the new method `upload_to`
        let file_path = "test_file_check.txt".to_string();
        let file_hash = iroh_blobs
            .upload_to(&collection_name, &file_path, rx)
            .await
            .expect("Failed to upload to collection");

        // Add the uploaded file to the collection
        let new_file_collection_hash = iroh_blobs
            .set_file(&collection_name, &file_path, &file_hash)
            .await
            .expect("Unable to add file to collection");
        assert!(
            !new_file_collection_hash.as_bytes().is_empty(),
            "New collection hash after uploading a file should not be empty"
        );

        sleep(Duration::from_secs(4)).await;

        let joined_group = backend2
            .join_from_url(&group1.get_url())
            .await
            .expect("Unable to join group on second peer");

        assert!(
            !new_file_collection_hash.as_bytes().is_empty(),
            "New collection hash after uploading a file should not be empty"
        );

        // Retry checking if peers have the hash
        let mut retries = 4;
        let mut peers_have = false;
        while retries > 0 {
            peers_have = joined_group
                .peers_have_hash(&file_hash)
                .await
                .unwrap_or(false);
            if peers_have {
                break;
            }
            retries -= 1;
            sleep(Duration::from_secs(4)).await;
        }

        assert!(peers_have, "Peers should have the uploaded hash");

        veilid_api1.shutdown().await;
        veilid_api2.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_collection_and_upload_file_via_backend() -> Result<()> {
        // Setup temporary directory for backend and veilid blobs
        let path = TmpDir::new("test_backend_create_collection").await.unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Step 1: Create a group via backend
        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Step 2: Create a collection via the backend's veilid_iroh_blobs instance
        let collection_name = "test_collection".to_string();

        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");
        let collection_hash = iroh_blobs
            .create_collection(&collection_name)
            .await
            .expect("Failed to create collection");

        assert!(
            !collection_hash.as_bytes().is_empty(),
            "Collection hash should not be empty"
        );

        // Step 3: Upload a file to the collection
        let file_path = path.as_ref().join("test_file.txt");
        let file_content = b"Test content for collection upload";
        fs::write(&file_path, file_content)
            .await
            .expect("Failed to write to file");

        let file_hash = iroh_blobs
            .upload_from_path(file_path.clone())
            .await
            .expect("Failed to upload file");
        assert!(
            !file_hash.as_bytes().is_empty(),
            "File hash should not be empty"
        );

        // Step 4: Add the file to the collection
        let updated_collection_hash = iroh_blobs
            .set_file(&collection_name, "test_file.txt", &file_hash)
            .await
            .expect("Failed to set file in collection");

        assert!(
            !updated_collection_hash.as_bytes().is_empty(),
            "Updated collection hash should not be empty"
        );

        // Step 5: Verify that the file is listed in the collection
        let file_list = iroh_blobs
            .list_files(&collection_name)
            .await
            .expect("Failed to list files in collection");
        assert_eq!(
            file_list.len(),
            1,
            "There should be one file in the collection"
        );
        assert_eq!(file_list[0], "test_file.txt", "File name should match");

        // Clean up
        backend.stop().await.expect("Unable to stop backend");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_file_from_collection_via_backend() -> Result<()> {
        // Setup temporary directory for backend and veilid blobs
        let path = TmpDir::new("test_backend_delete_file").await.unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Step 1: Create a group via backend
        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Step 2: Create a collection via the backend's veilid_iroh_blobs instance
        let collection_name = "test_delete_collection".to_string();

        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        let collection_hash = iroh_blobs
            .create_collection(&collection_name)
            .await
            .expect("Failed to create collection");

        assert!(
            !collection_hash.as_bytes().is_empty(),
            "Collection hash should not be empty"
        );

        // Step 3: Upload a file to the collection
        let file_path = path.as_ref().join("test_file_to_delete.txt");
        let file_content = b"File content to be deleted";
        fs::write(&file_path, file_content)
            .await
            .expect("Failed to write to file");

        let file_hash = iroh_blobs
            .upload_from_path(file_path.clone())
            .await
            .expect("Failed to upload file");
        assert!(
            !file_hash.as_bytes().is_empty(),
            "File hash should not be empty"
        );

        // Step 4: Add the file to the collection
        let updated_collection_hash = iroh_blobs
            .set_file(&collection_name, "test_file_to_delete.txt", &file_hash)
            .await
            .expect("Failed to set file in collection");
        assert!(
            !updated_collection_hash.as_bytes().is_empty(),
            "Updated collection hash should not be empty"
        );

        // Step 5: Delete the file from the collection
        let new_collection_hash = iroh_blobs
            .delete_file(&collection_name, "test_file_to_delete.txt")
            .await
            .expect("Failed to delete file from collection");
        assert!(
            !new_collection_hash.as_bytes().is_empty(),
            "New collection hash after deletion should not be empty"
        );

        // Step 6: Verify that the file was deleted
        let file_list_after_deletion = iroh_blobs
            .list_files(&collection_name)
            .await
            .expect("Failed to list files in collection");
        assert!(
            file_list_after_deletion.is_empty(),
            "The collection should be empty after deleting the file"
        );

        // Clean up
        backend.stop().await.expect("Unable to stop backend");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_repo_collection_management() -> Result<()> {
        // Setup a temporary directory and initialize the backend
        let path = TmpDir::new("test_repo_collection_management")
            .await
            .unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        // Initialize the backend
        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Step 1: Create a group
        let mut group = backend
            .create_group()
            .await
            .expect("Failed to create group");

        // Step 2: Create a repo and verify it can write (i.e., has a secret key)
        let mut repo = group.create_repo().await.expect("Failed to create repo");

        assert!(repo.can_write(), "Repo should have write access");

        // Step 3: Set the repo name
        let repo_name = "Test Repo";

        repo.set_name(repo_name)
            .await
            .expect("Unable to set repo name");

        // Step 5: Upload a file, which implicitly creates the collection
        let file_name = "example.txt";
        let file_content = b"Test content for file upload";

        // Upload the file (this will automatically create or get the collection)
        let file_hash = repo.upload(file_name, file_content.to_vec()).await?;
        assert!(
            !file_hash.as_bytes().is_empty(),
            "File hash should not be empty after upload"
        );

        // Step 6: Use iroh_blobs set_file to update the collection with the uploaded file
        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        let collection_name = repo.get_name().await.expect("Failed to get repo name");
        let updated_collection_hash = repo
            .set_file_and_update_dht(&collection_name, file_name, &file_hash)
            .await?;
        assert!(
            !updated_collection_hash.as_bytes().is_empty(),
            "Updated collection hash should not be empty after adding file"
        );

        // Step 7: Verify the file is listed in the collection
        let file_list = repo.list_files().await?;
        assert_eq!(
            file_list.len(),
            1,
            "There should be one file in the collection"
        );
        assert_eq!(
            file_list[0], file_name,
            "The listed file should match the uploaded file"
        );

        // Step 8: Retrieve the file hash from the collection and verify it matches the uploaded hash
        let retrieved_file_hash = repo.get_file_hash(file_name).await?;
        assert_eq!(
            file_hash, retrieved_file_hash,
            "The retrieved file hash should match the uploaded file hash"
        );

        // Step 9: Delete the file from the collection
        let collection_hash_after_deletion = repo.delete_file(file_name).await?;
        assert!(
            !collection_hash_after_deletion.as_bytes().is_empty(),
            "Collection hash should not be empty after file deletion"
        );

        // Step 10: Verify the file is no longer listed in the collection
        let file_list_after_deletion = repo.list_files().await?;
        assert!(
            file_list_after_deletion.is_empty(),
            "The file list should be empty after deleting the file"
        );

        // Final Step -> Clean up
        backend.stop().await.expect("Unable to stop backend");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_collection_hash_consistency() -> Result<()> {
        // Setup temporary directory and initialize the backend
        let path = TmpDir::new("test_backend_collection_hash_consistency")
            .await
            .unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        // Step 1: Create a group and a collection
        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        let collection_name = "hash_consistency_collection".to_string();

        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");

        // Step 2: Create collection and get initial hash
        let initial_collection_hash = iroh_blobs
            .create_collection(&collection_name)
            .await
            .expect("Failed to create collection");

        // Step 3: Upload a file to the collection
        let file_path = path.as_ref().join("file1.txt");
        let file_content = b"Content of file 1";
        fs::write(&file_path, file_content)
            .await
            .expect("Failed to write file 1");

        let file_hash = iroh_blobs
            .upload_from_path(file_path.clone())
            .await
            .expect("Failed to upload file 1");
        let updated_collection_hash = iroh_blobs
            .set_file(&collection_name, "file1.txt", &file_hash)
            .await
            .expect("Failed to set file in collection");

        // Verify that the collection hash changed after adding a file
        assert_ne!(
            initial_collection_hash, updated_collection_hash,
            "The collection hash should change after a file is added"
        );

        // Step 4: Remove the file and verify the hash changes again
        let final_collection_hash = iroh_blobs
            .delete_file(&collection_name, "file1.txt")
            .await
            .expect("Failed to delete file from collection");

        assert_ne!(
            updated_collection_hash, final_collection_hash,
            "The collection hash should change after a file is removed"
        );

        // Clean up
        backend.stop().await.expect("Unable to stop backend");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rpc_service_init() -> Result<()> {
        // Setup temporary directory and initialize the backend
        let path = TmpDir::new("test_rpc_service_init").await.unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let rpc_instance = RpcService::from_backend(&backend).await?;

        backend.stop().await.expect("Unable to stop backend");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rpc_client() -> Result<()> {
        // Setup temporary directory and initialize the backend
        let path = TmpDir::new("test_rpc_client").await.unwrap();
        fs::create_dir_all(path.as_ref())
            .await
            .expect("Failed to create base directory");

        let (veilid2, _) = init_veilid(
            &path.to_path_buf().join("client"),
            "save-dweb-backup".to_string(),
        )
        .await?;

        let mut backend = Backend::new(path.as_ref()).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");

        let rpc_instance = RpcService::from_backend(&backend).await?;

        let rpc_instance_updater = RpcService::from_backend(&backend).await?;

        tokio::spawn(async move {
            rpc_instance_updater.start_update_listener().await.unwrap();
        });

        rpc_instance.set_name("Example").await?;

        let url = rpc_instance.get_descriptor_url();

        tokio::time::sleep(Duration::from_secs(2)).await;

        let client = RpcClient::from_veilid(veilid2.clone(), &url).await?;

        let name = client.get_name().await?;

        assert_eq!(name, "Example", "Unable to get name");

        let list = client.list_groups().await?;

        assert_eq!(list.group_ids.len(), 0, "No groups on init");

        backend.stop().await.expect("Unable to stop backend");
        veilid2.shutdown().await;
        Ok(())
    }
}
