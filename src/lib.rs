pub mod group;
pub mod repo;
pub mod backend;
pub mod common;
pub mod constants;

use crate::constants::{GROUP_NOT_FOUND, UNABLE_TO_SET_GROUP_NAME, UNABLE_TO_GET_GROUP_NAME, TEST_GROUP_NAME, UNABLE_TO_STORE_KEYPAIR, FAILED_TO_LOAD_KEYPAIR, KEYPAIR_NOT_FOUND, FAILED_TO_DESERIALIZE_KEYPAIR, ROUTE_ID_DHT_KEY,
 YES, NO, ASK, DATA, DONE};

use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use veilid_core::{
    vld0_generate_keypair, TypedKey, CRYPTO_KIND_VLD0, VeilidUpdate, VALID_CRYPTO_KINDS,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use iroh_blobs::Hash;

use serial_test::serial;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::fs;
    use bytes::Bytes;
    use std::path::Path;
    use tokio::sync::mpsc;
    use tokio::time::Duration;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::StreamExt;
    use tmpdir::TmpDir;
    use anyhow::Result;

    #[tokio::test]
    #[serial]
    async fn blob_transfer_test() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();
        let port = 8080;
    
        fs::create_dir_all(path.as_ref()).await.expect("Failed to create base directory");
    
        // Initialize the backend
        let mut backend = Backend::new(path.as_ref(), port).expect("Unable to create Backend");
        backend.start().await.expect("Unable to start");
    
        // Create a group and a repo
        let group = backend.create_group().await.expect("Unable to create group");
        let repo = backend.create_repo().await.expect("Unable to create repo");
    
        let iroh_blobs = repo.iroh_blobs.as_ref().expect("iroh_blobs not initialized");
    
        // Prepare data to upload as a blob
        let data_to_upload = b"Test data for blob".to_vec();
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(data_to_upload.clone()))).await.unwrap();
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
    async fn basic_test() -> Result<()> {
        let path = TmpDir::new("test_dweb_backend").await.unwrap();
        let port = 8080;

        fs::create_dir_all(path.as_ref()).await.expect("Failed to create base directory");

        let mut backend = Backend::new(path.as_ref(), port).expect("Unable to create Backend");

        backend.start().await.expect("Unable to start");
        let group = backend.create_group().await.expect("Unable to create group");

        group.set_name(TEST_GROUP_NAME).await.expect(UNABLE_TO_SET_GROUP_NAME);
        let name = group.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(name, TEST_GROUP_NAME);

        backend.stop().await.expect("Unable to stop");

        backend.start().await.expect("Unable to restart");
        let mut loaded_group = backend.get_group(TypedKey::new(CRYPTO_KIND_VLD0, group.id())).await.expect(GROUP_NOT_FOUND);

        let protected_store = backend.get_protected_store().unwrap();
        let keypair_data = protected_store.load_user_secret(group.id().to_string())
            .await
            .expect(FAILED_TO_LOAD_KEYPAIR)
            .expect(KEYPAIR_NOT_FOUND);
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data).expect(FAILED_TO_DESERIALIZE_KEYPAIR);

        // Check that the id matches group.id()
        assert_eq!(retrieved_keypair.id, group.id());

        // Check that the public_key matches the owner public key from the DHT record
        assert_eq!(retrieved_keypair.public_key, loaded_group.get_dht_record().owner().clone());

        // Check that the secret and encryption keys match
        assert_eq!(retrieved_keypair.secret_key, group.get_secret_key());
        assert_eq!(retrieved_keypair.encryption_key, group.get_encryption_key());

        // Check if we can get group name
        let group_name = loaded_group.get_name().await.expect(UNABLE_TO_GET_GROUP_NAME);
        assert_eq!(group_name, TEST_GROUP_NAME);

        // Compare the loaded group's id with the retrieved id
        assert_eq!(loaded_group.id(), retrieved_keypair.id);

        // Create a repo
        let repo = backend.create_repo().await.expect("Unable to create repo");
        let repo_key = repo.get_id();
        let repo_name = "Test Repo";

        // Set and get repo name
        repo.set_name(repo_name).await.expect("Unable to set repo name");
        let name = repo.get_name().await.expect("Unable to get repo name");
        assert_eq!(name, repo_name);

        // Add repo to group
        loaded_group.add_repo(repo.clone()).await.expect("Unable to add repo to group");

        // List known repos
        let repos = loaded_group.list_repos().await;
        assert!(repos.contains(&repo_key));

        // Retrieve repo by key
        let loaded_repo = backend.get_repo(repo_key.clone()).await.expect("Repo not found");

        // Check if repo name is correctly retrieved
        let retrieved_name = loaded_repo.get_name().await.expect("Unable to get repo name after restart");
        assert_eq!(retrieved_name, repo_name);

        // Get the update receiver from the backend
        let update_rx = backend.subscribe_updates().expect("Failed to subscribe to updates");

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

        // Get VeilidAPI instance from backend
        let veilid_api = backend.get_veilid_api().expect("Failed to get VeilidAPI instance");

        println!("Creating a new custom private route with valid crypto kinds: {:?}", VALID_CRYPTO_KINDS);

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
        loaded_repo
            .store_route_id_in_dht(route_id_blob.clone())
            .await
            .expect("Failed to store route ID blob in DHT");

        // Define the message to send
        let message = b"Test Message to Repo Owner".to_vec();

        println!("Sending message to owner...");

        // Send the message
        loaded_repo
            .send_message_to_owner(veilid_api, message.clone(), ROUTE_ID_DHT_KEY)
            .await
            .expect("Failed to send message to repo owner");

        // Receive the message
        let received_app_message = message_rx.recv().await.expect("Failed to receive message");

        // Verify the message
        assert_eq!(received_app_message.message(), message.as_slice());

        // Access the VeilidIrohBlobs instance
        let iroh_blobs = repo
            .iroh_blobs
            .as_ref()
            .expect("iroh_blobs not initialized");

        // Upload a blob from data_to_upload
        let data_to_upload = b"Test data for blob".to_vec();

        // Create a stream (Receiver) from data_to_upload
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(data_to_upload.clone()))).await.unwrap();
        drop(tx); // Close the sender

        // Upload from stream
        let hash = iroh_blobs
            .upload_from_stream(rx)
            .await
            .expect("Failed to upload blob");

        // After uploading the blob
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Get the route_id_blob from iroh_blobs
        let route_id_blob = iroh_blobs.route_id_blob();

        // Get VeilidAPI instance from backend
        let veilid_api = backend.get_veilid_api().expect("Failed to get VeilidAPI instance");

        // Get update_rx from backend
        let mut update_rx = backend.subscribe_updates().expect("Failed to get update receiver");

        // Call download_blob
        loaded_repo.download_blob(veilid_api, &mut update_rx, route_id_blob, &hash).await?;

        // Retrieve the data from the store
        let receiver = iroh_blobs
            .read_file(hash)
            .await
            .expect("Failed to get blob");

        let mut retrieved_data = Vec::new();

        // Read data from the receiver
        let mut stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => retrieved_data.extend_from_slice(bytes.as_ref()),
                Err(e) => panic!("Error reading data: {:?}", e),
            }
        }

        // Verify the data
        assert_eq!(retrieved_data, data_to_upload);

        backend.stop().await.expect("Unable to stop");
        Ok(())
    }
    
}
