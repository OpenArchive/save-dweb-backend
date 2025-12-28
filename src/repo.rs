use crate::common::DHTEntity;
use anyhow::{anyhow, Result};
use async_stream::stream;
use bytes::{BufMut, Bytes, BytesMut};
use core::hash;
use futures_core::stream::Stream;
use hex::{decode, ToHex};
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;
use std::collections::HashMap;
use std::sync::Arc;
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};
use veilid_core::{
    PublicKey, SecretKey, RecordKey, CryptoTyped, DHTRecordDescriptor, Nonce, ProtectedStore, RoutingContext,
    SharedSecret, Target, VeilidAPI, VeilidUpdate, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

pub const HASH_SUBKEY: u32 = 1;
pub const ROUTE_SUBKEY: u32 = 2;

#[derive(Clone)]
pub struct Repo {
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<SecretKey>,
    pub routing_context: RoutingContext,
    pub veilid: VeilidAPI,
    pub iroh_blobs: VeilidIrohBlobs,
}

impl Repo {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<SecretKey>,
        routing_context: RoutingContext,
        veilid: VeilidAPI,
        iroh_blobs: VeilidIrohBlobs,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            veilid,
            iroh_blobs,
        }
    }

    pub fn id(&self) -> RecordKey {
        self.dht_record.key().value
    }

    pub fn can_write(&self) -> bool {
        self.secret_key.is_some()
    }

    pub async fn update_route_on_dht(&self) -> Result<()> {
        let route_id_blob = self.iroh_blobs.route_id_blob().await;

        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                ROUTE_SUBKEY,
                route_id_blob,
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {}", e))?;

        Ok(())
    }

    pub async fn has_hash(&self, hash: &Hash) -> Result<bool> {
        if self.can_write() {
            Ok(self.iroh_blobs.has_hash(hash).await)
        } else {
            let route_id = self.get_route_id_blob().await?;
            self.iroh_blobs.ask_hash(route_id, *hash).await
        }
    }

    pub async fn get_route_id_blob(&self) -> Result<Vec<u8>> {
        if self.can_write() {
            let blob = self.iroh_blobs.route_id_blob().await;
            info!("Retrieved route ID blob for writable repo {}", self.id().encode_hex::<String>());
            return Ok(blob);
        }

        info!(
            "Getting route ID blob from DHT for repo {} subkey {}",
            self.dht_record.key().value.encode_hex::<String>(),
            ROUTE_SUBKEY
        );
        
        let value = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), ROUTE_SUBKEY, true)
            .await?;
        
        let value = match value {
            Some(v) => {
                info!("Route ID blob found in DHT for repo {}", self.id().encode_hex::<String>());
                v
            }
            None => {
                return Err(anyhow!(
                    "Unable to get DHT value for route id blob. Repo owner may not have published route yet."
                ));
            }
        };

        Ok(value.data().to_vec())
    }

    pub async fn get_file_stream(
        &self,
        file_name: &str,
    ) -> Result<impl Stream<Item = std::io::Result<Bytes>>> {
        let hash = self.get_file_hash(file_name).await?;
        // download the blob
        let receiver = self.iroh_blobs.read_file(hash.clone()).await?;

        let stream = ReceiverStream::new(receiver);

        Ok(stream)
    }

    pub async fn update_hash_on_dht(&self, hash: &Hash) -> Result<()> {
        // Convert hash to hex for DHT storage
        let root_hash_hex = hash.to_hex();
        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                HASH_SUBKEY,
                root_hash_hex.clone().into(),
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store collection blob in DHT: {}", e))?;

        Ok(())
    }

    pub async fn get_hash_from_dht(&self) -> Result<Hash> {
        let repo_id = self.dht_record.key().value.encode_hex::<String>();
        info!(
            "Getting hash from DHT for repo {} subkey {}",
            repo_id,
            HASH_SUBKEY
        );

        // Retry up to 5 times with exponential backoff
        let max_retries = 5;
        let mut retry_count = 0;
        let mut backoff_ms = 500;

        loop {
            let value = self
                .routing_context
                .get_dht_value(self.dht_record.key().clone(), HASH_SUBKEY, true)
                .await?;

            match value {
                Some(v) => {
                    // Successfully got value, decode and return
                    let data = v.data();

                    // Decode the hex string (64 bytes) into a 32-byte hash
                    let decoded_hash = match decode(data) {
                        Ok(h) => h,
                        Err(e) => {
                            return Err(anyhow!(
                                "Failed to decode hex string from DHT: {}. Repo hash may be corrupted.",
                                e
                            ));
                        }
                    };

                    // Ensure the decoded hash is 32 bytes
                    if decoded_hash.len() != 32 {
                        return Err(anyhow!(
                            "Invalid hash length: expected 32 bytes, got {} bytes. Repo hash may be corrupted.",
                            decoded_hash.len()
                        ));
                    }
                    let mut hash_raw: [u8; 32] = [0; 32];
                    hash_raw.copy_from_slice(&decoded_hash);

                    // Now create the Hash object
                    let hash = Hash::from_bytes(hash_raw);

                    info!("Successfully retrieved hash from DHT: {}", hash.to_hex());
                    return Ok(hash);
                }
                None => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        info!(
                            "DHT value not found for repo {} after {} retries",
                            repo_id, max_retries
                        );
                        return Err(anyhow!(
                            "Unable to get DHT value for repo root hash after {} retries. \
                             Repo may be empty or hash not yet published to DHT.",
                            max_retries
                        ));
                    }

                    info!(
                        "DHT value not found, retry {}/{} in {}ms",
                        retry_count, max_retries, backoff_ms
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2; // Exponential backoff
                }
            }
        }
    }

    pub async fn update_collection_on_dht(&self) -> Result<()> {
        let collection_hash = self.get_collection_hash().await?;
        self.update_hash_on_dht(&collection_hash).await
    }

    pub async fn upload_blob(&self, file_path: PathBuf) -> Result<Hash> {
        if !self.can_write() {
            return Err(anyhow!("Cannot upload blob, repo is not writable"));
        }
        // Use repo id as key for a collection
        // Upload the file and get the hash
        let hash = self.iroh_blobs.upload_from_path(file_path).await?;

        self.update_hash_on_dht(&hash).await?;
        Ok(hash)
    }

    // Method to get or create a collection associated with the repo
    async fn get_or_create_collection(&self) -> Result<Hash> {
        if !self.can_write() {
            // Try to get the collection hash from the DHT (remote or unwritable repos)
            match self.get_hash_from_dht().await {
                Ok(collection_hash) => {
                    // The collection hash is found, return it directly (no need for a name)
                    info!("Collection hash found in DHT: {}", collection_hash.to_hex());
                    return Ok(collection_hash);
                }
                Err(e) => {
                    // Log the error but provide more context
                    warn!(
                        "Collection hash not found in DHT for read-only repo {}: {}. This may be normal for empty repos.",
                        self.id().encode_hex::<String>(),
                        e
                    );
                    // Error if we're trying to create a collection in a read-only repo
                    return Err(anyhow::Error::msg(format!(
                        "Collection not found and cannot create in read-only repo. Error: {}",
                        e
                    )));
                }
            }
        }
        // If the repo is writable, check if the collection exists
        // Use repo ID as namespace to guarantee uniqueness across groups
        let repo_id = self.id().encode_hex::<String>();
        let collection_name = format!("repo_{}", repo_id);

        // Try new naming scheme first
        match self.iroh_blobs.collection_hash(&collection_name).await {
            Ok(collection_hash) => {
                // Collection exists with new naming, return the hash
                info!("Collection found for {}: {}", collection_name, collection_hash.to_hex());
                return Ok(collection_hash);
            }
            Err(_) => {
                // Migration: check if old name exists
                let legacy_name = self.get_name().await.ok();
                if let Some(old_name) = legacy_name {
                    if let Ok(old_hash) = self.iroh_blobs.collection_hash(&old_name).await {
                        info!("Migrating collection from '{}' to '{}'", old_name, collection_name);
                        // Note: Can't rename in Iroh, but we use the old hash
                        // Just update DHT with the existing hash
                        if let Err(e) = self.update_hash_on_dht(&old_hash).await {
                            warn!("Failed to update hash on DHT during migration: {}", e);
                        }
                        return Ok(old_hash);
                    }
                }

                // Create new collection with namespaced name
                info!("Creating new collection for repo {} with name {}", repo_id, collection_name);
                let new_hash = match self.iroh_blobs.create_collection(&collection_name).await {
                    Ok(hash) => {
                        info!("New collection created with hash: {}", hash.to_hex());
                        hash
                    }
                    Err(e) => {
                        error!("Failed to create collection: {e:?}");
                        return Err(anyhow!("Failed to create collection for repo {}: {}", repo_id, e));
                    }
                };

                // Update the DHT with the new collection hash
                if let Err(e) = self.update_collection_on_dht().await {
                    error!("Failed to update DHT with new collection hash: {e:?}");
                    return Err(anyhow!("Failed to update DHT with collection hash for repo {}: {}", repo_id, e));
                }

                info!("DHT updated with new collection hash: {}", new_hash.to_hex());
                // Return the new collection hash
                Ok(new_hash)
            }
        }
    }

    // Method to retrieve a file's hash from the collection
    pub async fn get_file_hash(&self, file_name: &str) -> Result<Hash> {
        // Ensure the collection exists before reading
        let collection_hash = self.get_or_create_collection().await?;

        self.iroh_blobs
            .get_file_from_collection_hash(&collection_hash, file_name)
            .await
    }

    pub async fn list_files(&self) -> Result<Vec<String>> {
        if self.can_write() {
            let hash = self.get_or_create_collection().await?;
            self.list_files_from_collection_hash(&hash).await
        } else {
            let got_hash = self.get_hash_from_dht().await;

            // Return empty list if we can't fetch from the DHT
            match got_hash {
                Ok(hash) => self.list_files_from_collection_hash(&hash).await,
                Err(_) => Ok(Vec::new()),
            }
        }
    }

    pub async fn list_files_from_collection_hash(
        &self,
        collection_hash: &Hash,
    ) -> Result<Vec<String>> {
        let file_list = self
            .iroh_blobs
            .list_files_from_hash(collection_hash)
            .await?;

        Ok(file_list)
    }

    // Method to delete a file from the collection
    pub async fn delete_file(&self, file_name: &str) -> Result<Hash> {
        self.check_write_permissions()?;

        // Ensure the collection exists before deleting a file
        let collection_hash = self.get_or_create_collection().await?;

        // Delete the file from the collection and get the new collection hash
        let deleted_hash = self
            .iroh_blobs
            .delete_file_from_collection_hash(&collection_hash, file_name)
            .await?;

        // Persist the new collection hash with the name to the store
        let collection_name = self.get_name().await?;
        self.iroh_blobs
            .persist_collection_with_name(&collection_name, &deleted_hash)
            .await?;

        // Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;

        Ok(deleted_hash)
    }

    // Method to get the collection's hash
    async fn get_collection_hash(&self) -> Result<Hash> {
        let collection_name = self.get_name().await?;

        self.iroh_blobs.collection_hash(&collection_name).await
    }

    /// Encrypt file data with group's encryption key
    /// Format: [MAGIC(4)] [VERSION(1)] [NONCE(24)] [ENCRYPTED_DATA]
    fn encrypt_file_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        const MAGIC: &[u8; 4] = b"SAVE"; // Magic bytes to identify encrypted files
        const VERSION: u8 = 0x01; // Encryption version

        let veilid = self.get_veilid_api();
        let crypto = veilid.crypto()?;
        let crypto_system = crypto
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

        let nonce = crypto_system.random_nonce();
        let encrypted_chunk = crypto_system
            .encrypt_aead(data, &nonce, &self.get_encryption_key(), None)
            .map_err(|e| anyhow!("Failed to encrypt file data: {}", e))?;

        // Build encrypted file: MAGIC + VERSION + NONCE + ENCRYPTED_DATA
        let mut buffer = Vec::with_capacity(4 + 1 + nonce.bytes.len() + encrypted_chunk.len());
        buffer.extend_from_slice(MAGIC);
        buffer.push(VERSION);
        buffer.extend_from_slice(&nonce.bytes);
        buffer.extend_from_slice(&encrypted_chunk);

        Ok(buffer)
    }

    /// Decrypt file data, auto-detecting encrypted vs plaintext
    /// Returns (decrypted_data, was_encrypted)
    pub fn decrypt_file_data(&self, data: &[u8]) -> Result<(Vec<u8>, bool)> {
        const MAGIC: &[u8; 4] = b"SAVE";

        // Check if file is encrypted (has magic bytes)
        if data.len() > 29 && &data[0..4] == MAGIC {
            let version = data[4];
            if version != 0x01 {
                return Err(anyhow!("Unsupported encryption version: {}", version));
            }

            let nonce_bytes: [u8; 24] = data[5..29]
                .try_into()
                .map_err(|_| anyhow!("Failed to extract nonce"))?;
            let nonce = Nonce::new(nonce_bytes);
            let encrypted_data = &data[29..];

            let veilid = self.get_veilid_api();
            let crypto = veilid.crypto()?;
            let crypto_system = crypto
                .get(CRYPTO_KIND_VLD0)
                .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

            let decrypted = crypto_system
                .decrypt_aead(encrypted_data, &nonce, &self.get_encryption_key(), None)
                .map_err(|e| anyhow!("Failed to decrypt file data: {}", e))?;

            Ok((decrypted, true))
        } else {
            // File is not encrypted (legacy/migration case)
            warn!("File not encrypted, returning plaintext data");
            Ok((data.to_vec(), false))
        }
    }

    pub async fn upload(&self, file_name: &str, data_to_upload: Vec<u8>) -> Result<Hash> {
        self.check_write_permissions()?;

        // Encrypt file data before uploading
        let encrypted_data = self.encrypt_file_data(&data_to_upload)?;
        info!("File encrypted: {} bytes → {} bytes", data_to_upload.len(), encrypted_data.len());

        // Ensure the collection exists before uploading
        let collection_hash = self.get_or_create_collection().await?;

        // Use the repo name
        let collection_name = self.get_name().await?;
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(encrypted_data)))
            .await
            .unwrap();
        drop(tx);

        let file_hash = self
            .iroh_blobs
            .upload_to(&collection_name, file_name, rx)
            .await?;

        // Persist the new collection hash with the name to the store
        self.iroh_blobs
            .persist_collection_with_name(&collection_name, &file_hash)
            .await?;

        // Update the collection hash on the DHT
        self.update_collection_on_dht().await?;

        Ok(file_hash)
    }

    pub async fn set_file_and_update_dht(
        &self,
        collection_name: &str,
        file_name: &str,
        file_hash: &Hash,
    ) -> Result<Hash> {
        // Step 1: Update the collection with the new file using `set_file`
        let updated_collection_hash = self
            .iroh_blobs
            .set_file(collection_name, file_name, file_hash)
            .await?;
        println!("Updated collection hash: {updated_collection_hash:?}");

        // Step 2: Persist the new collection hash locally
        self.iroh_blobs
            .persist_collection_with_name(collection_name, &updated_collection_hash)
            .await?;
        println!(
            "Collection persisted with new hash: {updated_collection_hash:?}"
        );

        // Step 3: Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;
        println!(
            "DHT updated with new collection hash: {updated_collection_hash:?}"
        );

        Ok(updated_collection_hash)
    }

    // Helper method to check if the repo can write
    fn check_write_permissions(&self) -> Result<()> {
        if !self.can_write() {
            return Err(anyhow::Error::msg("Repo does not have write permissions"));
        }
        Ok(())
    }
}

impl DHTEntity for Repo {
    fn get_id(&self) -> RecordKey {
        self.id()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.encryption_key.clone()
    }

    fn get_routing_context(&self) -> RoutingContext {
        self.routing_context.clone()
    }

    fn get_veilid_api(&self) -> VeilidAPI {
        self.veilid.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<SecretKey> {
        self.secret_key
    }
}
