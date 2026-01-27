#![recursion_limit = "256"]
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
    PublicKey, SecretKey, RecordKey, VeilidUpdate, CRYPTO_KIND_VLD0,
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
    use common::make_route;
    use common::test_helpers::setup_test_backend;
    use crate::rpc::{RpcClient, RpcService};
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::fs;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use tokio_stream::wrappers::ReceiverStream;
    use tracing::error;
    use tmpdir::TmpDir;

    #[tokio::test]
    #[serial]
    async fn sending_message_via_private_route() -> Result<()> {
        let (backend, _tmpdir) = setup_test_backend("test_dweb_backend").await?;

        // Use tokio::select! to ensure cleanup happens even on timeout
        // Replace expect() with ? to convert panics to errors, ensuring cleanup runs
        let result = tokio::select! {
            result = async {
                // Add delay to ensure backend initialization
                tokio::time::sleep(Duration::from_secs(2)).await;

                // Create a group and a repo - use ? instead of expect() to avoid panics
                let mut group = backend
                    .create_group()
                    .await?;
                let repo = group.create_repo().await?;
                let veilid_api = backend
                    .get_veilid_api()
                    .await
                    .ok_or_else(|| anyhow!("Failed to get VeilidAPI instance"))?;

                // Get the update receiver from the backend
                let update_rx = backend
                    .subscribe_updates()
                    .await
                    .ok_or_else(|| anyhow!("Failed to subscribe to updates"))?;

                // Set up a channel to receive AppMessage updates
                let (message_tx, mut message_rx) = mpsc::channel(1);

                // Spawn a task to listen for updates
                // Exit cleanly if receiver is dropped to avoid masking failures
                let listener_handle = tokio::spawn(async move {
                    let mut rx = update_rx.resubscribe();
                    while let Ok(update) = rx.recv().await {
                        if let VeilidUpdate::AppMessage(app_message) = update {
                            // If send fails (receiver dropped), exit to surface failure quickly
                            if message_tx.send(app_message).await.is_err() {
                                tracing::debug!("Message receiver dropped, listener task exiting");
                                break;
                            }
                        }
                    }
                });

                println!(
                    "Creating a new custom private route with valid crypto kinds: {VALID_CRYPTO_KINDS:?}"
                );

                // Create a new private route
                let (route_id, route_id_blob) = make_route(&veilid_api)
                    .await?;

                // Store the route_id_blob in DHT
                repo.store_route_id_in_dht(route_id_blob.clone())
                    .await?;

                // Define the message to send
                let message = b"Test Message to Repo Owner".to_vec();

                println!("Sending message to owner...");

                // Send the message
                repo.send_message_to_owner(&veilid_api, message.clone(), ROUTE_ID_DHT_KEY)
                    .await?;

                // Receive the message from the background task with a shorter timeout
                // This ensures failures surface quickly instead of waiting the full 888s
                let receive_timeout = Duration::from_secs(30);
                let received_app_message = tokio::time::timeout(receive_timeout, message_rx.recv())
                    .await
                    .map_err(|_| anyhow!("Timeout waiting to receive message ({}s)", receive_timeout.as_secs()))?
                    .ok_or_else(|| anyhow!("Message receiver channel closed before message received"))?;

                // Verify the message
                // Note: assert_eq! will still panic on failure, but that's expected test behavior
                assert_eq!(received_app_message.message(), message.as_slice());

                Ok::<(), anyhow::Error>(())
            } => result,
            _ = tokio::time::sleep(Duration::from_secs(888)) => {
                Err(anyhow::anyhow!("Test timed out after 888 seconds"))
            }
        };

        // Ensure cleanup happens regardless of success, timeout, or error
        // This will run for all error paths (via ?) and timeout paths
        // Note: If assert_eq! panics, cleanup won't run, but that's expected test behavior
        if let Err(e) = backend.stop().await {
            tracing::warn!("Failed to stop backend during cleanup: {e}");
        }

        // Return the test result
        result?;

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
        backend.start_with_namespace(Some("known_group_persistence".to_string())).await.expect("Unable to start");

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

        backend.start_with_namespace(Some("known_group_persistence".to_string())).await.expect("Unable to restart");

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
        backend.start_with_namespace(Some("group_name_persistence".to_string())).await.expect("Unable to start");

        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");
        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");

        backend.start_with_namespace(Some("group_name_persistence".to_string())).await.expect("Unable to restart");
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
        backend.start_with_namespace(Some("repo_persistence".to_string())).await.expect("Unable to start backend");

        let mut group = backend
            .create_group()
            .await
            .expect("Failed to create group");
        let group_id = group.id();

        // Drop the group and stop the backend
        drop(group);
        backend.stop().await.expect("Unable to stop backend");

        // Restart backend and verify group and repo persistence
        backend.start_with_namespace(Some("repo_persistence".to_string())).await.expect("Unable to restart backend");
        println!(
            "Backend restarted, attempting to load group with ID: {group_id:?}"
        );

        let mut reload_group = backend.get_group(&group_id).await.expect(GROUP_NOT_FOUND);
        let loaded_group_id = reload_group.id();

        // Drop the group and stop the backend
        drop(reload_group);
        backend.stop().await.expect("Unable to stop backend");

        // Restart backend and verify group and repo persistence
        backend.start_with_namespace(Some("repo_persistence".to_string())).await.expect("Unable to restart backend");
        println!(
            "Backend restarted, attempting to load group with ID: {loaded_group_id:?}"
        );

        let mut loaded_group = backend
            .get_group(&loaded_group_id)
            .await
            .expect(GROUP_NOT_FOUND);
        println!("group reloaded with id: {loaded_group_id:?}");
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
        println!("lib: Repo created with id: {repo_id:?}");

        // Check if the repo is listed after restart
        let list = loaded_group.list_repos().await;
        assert_eq!(list.len(), 1, "One repo got loaded back");

        let loaded_repo = loaded_group
            .get_own_repo()
            .await
            .expect("Repo not found after restart");

        println!("a list of repos: {list:?}");

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
            .start_with_namespace(Some("repo_persistence".to_string()))
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

        println!("Another list of repos: {another_list:?}");

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
        let (backend, tmpdir) = setup_test_backend("upload_blob_test").await?;
        let path = tmpdir.to_path_buf();

        // Create a group
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Prepare a temporary file to upload as a blob
        let tmp_file_path = path.join("test_blob_file.txt");
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
                Err(e) => panic!("Error reading data: {e:?}"),
            }
        }

        // Verify that the downloaded data matches the original file content
        assert_eq!(retrieved_data, file_content);

        backend.stop().await.expect("Unable to stop");

        // Give Veilid time to fully shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
    #[tokio::test]
    #[serial]
    async fn upload_blob_and_verify_protected_store() -> Result<()> {
        let (backend, tmpdir) = setup_test_backend("upload_blob_and_verify_protected_store").await?;
        let path = tmpdir.to_path_buf();

        // Create a group
        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        // Prepare a temporary file to upload as a blob
        let tmp_file_path = path.join("test_blob_file.txt");
        let file_content = b"Test content for file upload";
        fs::write(&tmp_file_path, file_content)
            .await
            .expect("Failed to write to temp file");

        let protected_store = backend
            .get_veilid_api()
            .await
            .unwrap()
            .protected_store()
            .unwrap();

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
                Err(e) => panic!("Error reading data: {e:?}"),
            }
        }

        // Verify that the downloaded data matches the original file content
        assert_eq!(retrieved_data, file_content);

        backend.stop().await.expect("Unable to stop");

        // Give Veilid time to fully shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    /// Upload and retrieve a 1 MiB blob to verify the iroh/veilid pipeline handles
    /// larger payloads. The DHT only stores the hash (~32–64 bytes); the blob
    /// content is transferred via veilid_iroh_blobs tunnels.
    #[tokio::test]
    #[serial]
    async fn upload_large_blob_test() -> Result<()> {
        const SIZE_1_MIB: usize = 1024 * 1024;
        let (backend, tmpdir) = setup_test_backend("upload_large_blob_test").await?;
        let path = tmpdir.to_path_buf();

        let mut group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        let tmp_file_path = path.join("large_blob.bin");
        let file_content: Vec<u8> = (0..SIZE_1_MIB).map(|i| (i % 256) as u8).collect();
        fs::write(&tmp_file_path, &file_content)
            .await
            .expect("Failed to write large temp file");

        let repo = group.create_repo().await?;

        let hash = repo
            .upload_blob(tmp_file_path.clone())
            .await
            .expect("Failed to upload large blob");

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
            let dht_value_bytes = dht_value_data.data();
            let dht_value_str = String::from_utf8(dht_value_bytes.to_vec())
                .expect("Failed to convert ValueData to String");
            assert_eq!(dht_value_str, hash.to_hex());
        } else {
            panic!("No value found in DHT for the given key");
        }

        let iroh_blobs = backend
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized");
        let receiver = iroh_blobs
            .read_file(hash.clone())
            .await
            .expect("Failed to read large blob");

        let mut retrieved_data = Vec::new();
        let mut stream = ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {e:?}"),
            }
        }

        assert_eq!(retrieved_data.len(), file_content.len());
        assert_eq!(retrieved_data, file_content);

        backend.stop().await.expect("Unable to stop");
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_join() {
        let (backend, _tmpdir) = setup_test_backend("test_join").await.expect("Unable to setup backend");
        let group = backend
            .create_group()
            .await
            .expect("Unable to create group");

        group
            .set_name(TEST_GROUP_NAME)
            .await
            .expect(UNABLE_TO_SET_GROUP_NAME);

        let url = group.get_url().expect("Failed to get group URL");

        let keys = backend::parse_url(url.as_str()).expect("URL was parsed back out");

        assert_eq!(keys.id, group.id());
        backend.stop().await.expect("Unable to stop");
    }

    #[tokio::test]
    #[serial]
    async fn list_repos_test() -> Result<()> {
        let (backend, _tmpdir) = setup_test_backend("list_repos_test").await?;

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
        let (backend, _tmpdir) = setup_test_backend("get_own_repo_test").await?;

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

        let (v1_result, v2_result) = tokio::join!(
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

        group.set_name("Example").await?;

        let mut peer_repo = group.create_repo().await?;

        sleep(Duration::from_secs(2)).await;

        let group2 = backend2.join_from_url(&group.get_url()?).await?;

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

        sleep(Duration::from_secs(2)).await;

        // Download hash from peers
        let mut retries = 10;
        while retries > 0 {
            if group2.download_hash_from_peers(&file_hash).await.is_ok() {
                println!("Download success!");
                break;
            }
            retries -= 1;
            sleep(Duration::from_secs(4)).await;
        }
        assert!(
            retries > 0,
            "Failed to download hash from peers after retries"
        );

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

        let (v1_result, v2_result) = tokio::join!(
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
            .join_from_url(&group1.get_url()?)
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

        backend1.stop().await?;
        backend2.stop().await?;
        // backend.stop() already shuts down the API, so no need for explicit shutdown
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_collection_and_upload_file_via_backend() -> Result<()> {
        // Setup temporary directory for backend and veilid blobs
        let (backend, tmpdir) = setup_test_backend("test_create_collection_and_upload_file_via_backend").await?;
        let path = tmpdir.to_path_buf();

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
        let file_path = path.join("test_file.txt");
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
        let (backend, tmpdir) = setup_test_backend("test_delete_file_from_collection_via_backend").await?;
        let path = tmpdir.to_path_buf();

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
        let file_path = path.join("test_file_to_delete.txt");
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
        let (backend, _tmpdir) = setup_test_backend("test_repo_collection_management").await?;

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

        let collection_name = repo.collection_name();
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
        let (backend, tmpdir) = setup_test_backend("test_collection_hash_consistency").await?;
        let path = tmpdir.to_path_buf();

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
        let file_path = path.join("file1.txt");
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
        let (backend, _tmpdir) = setup_test_backend("test_rpc_service_init").await?;

        let rpc_instance = RpcService::from_backend(&backend).await?;

        backend.stop().await.expect("Unable to stop backend");

        // Give Veilid time to fully shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rpc_client() -> Result<()> {
        // Setup temporary directory and initialize the backend
        let (backend, tmpdir) = setup_test_backend("test_rpc_client").await?;
        let path = tmpdir.to_path_buf();

        println!("Initializing client Veilid instance...");
        let (veilid2, _) = init_veilid(
            &path.join("client"),
            "save-dweb-backup-client".to_string(),
        )
        .await
        .map_err(|e| anyhow!("Failed to init client Veilid: {e}"))?;

        println!("Backend already started via setup_test_backend");

        println!("Creating RPC service...");
        let rpc_instance = RpcService::from_backend(&backend).await?;

        println!("Starting RPC service listener...");
        let rpc_listener = rpc_instance.clone();
        tokio::spawn(async move {
            if let Err(e) = rpc_listener.start_update_listener().await {
                error!("RPC listener error: {}", e);
            }
        });

        println!("Setting RPC service name...");
        rpc_instance.set_name("Example").await?;

        let url = rpc_instance.get_descriptor_url()?;
        println!("RPC service URL: {url}");

        // Wait longer for DHT propagation between two separate Veilid instances
        println!("Waiting 10 seconds for DHT propagation...");
        tokio::time::sleep(Duration::from_secs(10)).await;

        println!("Creating RPC client...");
        let client = RpcClient::from_veilid(veilid2.clone(), &url).await
            .map_err(|e| anyhow!("Failed to create RPC client: {e}"))?;

        println!("Getting name from RPC service...");
        let name = client.get_name().await
            .map_err(|e| anyhow!("Failed to get name: {e}"))?;

        assert_eq!(name, "Example", "Unable to get name");

        println!("Listing groups...");
        let list = client.list_groups().await
            .map_err(|e| anyhow!("Failed to list groups: {e}"))?;

        assert_eq!(list.group_ids.len(), 0, "No groups on init");

        println!("Stopping backend...");
        backend.stop().await.expect("Unable to stop backend");
        veilid2.shutdown().await;

        // Give Veilid time to fully shutdown
        tokio::time::sleep(Duration::from_millis(500)).await;
        println!("Test completed successfully!");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_auto_create_repo_on_join_group() -> Result<()> {
        // This test verifies the fix for cross-device sharing issue:
        // When Device B joins a group created by Device A, it should automatically
        // create its own repo so it can upload files.

        let base_dir = TmpDir::new("test_auto_create_repo_on_join")
            .await
            .unwrap();

        let base_dir_path = base_dir.to_path_buf();

        // Create separate stores for each device
        let store1 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh1")).await?;
        let store2 =
            iroh_blobs::store::fs::Store::load(base_dir.to_path_buf().join("iroh2")).await?;

        // Initialize two separate Veilid instances (simulating two devices)
        let (v1_result, v2_result) = tokio::join!(
            init_veilid(&base_dir_path, "device_a".to_string()),
            init_veilid(&base_dir_path, "device_b".to_string())
        );
        let (veilid_api1, mut update_rx1) = v1_result?;
        let (veilid_api2, mut update_rx2) = v2_result?;

        fs::create_dir_all(base_dir.as_ref())
            .await
            .expect("Failed to create base directory");

        // Create Device A backend
        let backend1 = Backend::from_dependencies(
            &base_dir.to_path_buf().join("device_a"),
            veilid_api1.clone(),
            update_rx1,
            store1,
        )
        .await
        .unwrap();

        // Create Device B backend
        let backend2 = Backend::from_dependencies(
            &base_dir.to_path_buf().join("device_b"),
            veilid_api2.clone(),
            update_rx2,
            store2,
        )
        .await
        .unwrap();

        // Step 1: Create a group on Device A
        let mut group1 = backend1
            .create_group()
            .await
            .expect("Unable to create group on Device A");

        group1.set_name("Test Group").await?;

        // Create a repo on Device A (optional, but simulates real usage)
        let _repo1 = group1.create_repo().await?;

        // Wait for DHT propagation
        sleep(Duration::from_secs(2)).await;

        // Step 2: Join the group on Device B using the group URL
        let group_url = group1.get_url().expect("Failed to get group URL");
        println!("Device A created group with URL: {group_url}");

        let mut group2 = backend2
            .join_from_url(&group_url)
            .await
            .expect("Unable to join group on Device B");

        // Step 3: Verify that Device B automatically created its own repo
        let own_repo = group2
            .get_own_repo()
            .await
            .expect("Device B should have its own repo after joining");

        assert!(
            own_repo.can_write(),
            "Device B's repo should have write permissions"
        );

        println!("Device B successfully auto-created repo with write permissions");

        // Step 4: Upload a file from Device B to verify it works
        let file_content = b"Test file from Device B";
        let file_path = base_dir.as_ref().join("device_b_file.txt");
        fs::write(&file_path, file_content)
            .await
            .expect("Failed to write test file");

        // Upload the file using Device B's repo
        let file_hash = own_repo
            .upload_blob(file_path.clone())
            .await
            .expect("Device B should be able to upload files");

        assert!(
            !file_hash.as_bytes().is_empty(),
            "File hash should not be empty after upload"
        );

        println!(
            "Device B successfully uploaded file with hash: {}",
            file_hash.to_hex()
        );

        // Step 5: Verify the file can be retrieved
        let iroh_blobs2 = backend2
            .get_iroh_blobs()
            .await
            .expect("iroh_blobs not initialized on Device B");

        let receiver = iroh_blobs2
            .read_file(file_hash.clone())
            .await
            .expect("Failed to read blob");

        let mut retrieved_data = Vec::new();
        let mut stream = ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {e:?}"),
            }
        }

        // Verify that the downloaded data matches the uploaded data
        assert_eq!(retrieved_data, file_content);

        println!("Test completed successfully - Device B can upload and retrieve files!");

        // Cleanup
        backend1.stop().await?;
        backend2.stop().await?;
        // backend.stop() already shuts down the API, so no need for explicit shutdown

        Ok(())
    }
}
