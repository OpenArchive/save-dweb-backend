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
    DHTRecordDescriptor, Nonce, ProtectedStore, PublicKey, RecordKey, RoutingContext, SecretKey,
    SetDHTValueOptions, SharedSecret, Target, VeilidAPI, VeilidUpdate, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

pub const HASH_SUBKEY: u32 = 1;
pub const ROUTE_SUBKEY: u32 = 2;
pub const ENCRYPTED_FILE_MAGIC: &[u8; 4] = b"SAVE";
const ENCRYPTED_FILE_VERSION: u8 = 0x01;
const ENCRYPTED_FILE_HEADER_LEN: usize = 4 + 1 + crate::common::AEAD_NONCE_LEN;

enum FileDataEnvelope<'a> {
    Plaintext(&'a [u8]),
    Encrypted { nonce: Nonce, ciphertext: &'a [u8] },
}

fn split_file_data_envelope(data: &[u8]) -> Result<FileDataEnvelope<'_>> {
    if data.len() < ENCRYPTED_FILE_MAGIC.len() || &data[..4] != ENCRYPTED_FILE_MAGIC {
        return Ok(FileDataEnvelope::Plaintext(data));
    }

    if data.len() <= ENCRYPTED_FILE_HEADER_LEN {
        return Ok(FileDataEnvelope::Plaintext(data));
    }

    let version = data[4];
    if version != ENCRYPTED_FILE_VERSION {
        return Err(anyhow!("Unsupported encryption version: {version}"));
    }

    let nonce_bytes: [u8; crate::common::AEAD_NONCE_LEN] = data[5..ENCRYPTED_FILE_HEADER_LEN]
        .try_into()
        .map_err(|_| anyhow!("Failed to extract nonce"))?;
    let ciphertext = &data[ENCRYPTED_FILE_HEADER_LEN..];
    Ok(FileDataEnvelope::Encrypted {
        nonce: Nonce::new(&nonce_bytes),
        ciphertext,
    })
}

fn hash_from_dht_bytes(data: &[u8]) -> Result<Hash> {
    let decoded_hash = decode(data).map_err(|e| {
        anyhow!("Failed to decode hex string from DHT: {e}. Repo hash may be corrupted.")
    })?;

    if decoded_hash.len() != 32 {
        return Err(anyhow!(
            "Invalid hash length: expected 32 bytes, got {} bytes. Repo hash may be corrupted.",
            decoded_hash.len()
        ));
    }

    let hash_raw: [u8; 32] = decoded_hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Invalid hash length after validation"))?;

    Ok(Hash::from_bytes(hash_raw))
}

fn ensure_write_permissions(can_write: bool) -> Result<()> {
    if !can_write {
        return Err(anyhow::Error::msg("Repo does not have write permissions"));
    }
    Ok(())
}

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
        self.dht_record.key().clone()
    }

    pub fn can_write(&self) -> bool {
        self.secret_key.is_some()
    }

    /// Get the stable collection name for this repo (namespaced by repo ID)
    /// This ensures collection names are unique across all repos and groups
    pub fn collection_name(&self) -> String {
        format!("repo_{}", hex::encode(self.id().opaque().ref_value()))
    }

    pub async fn update_route_on_dht(&self) -> Result<()> {
        let route_id_blob = self.iroh_blobs.route_id_blob().await;

        info!(
            "Updating route ID on DHT for repo {} (route blob size: {} bytes)",
            hex::encode(self.id().opaque().ref_value()),
            route_id_blob.len()
        );

        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                ROUTE_SUBKEY,
                route_id_blob,
                Some(SetDHTValueOptions::default()),
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {e}"))?;

        info!(
            "Successfully updated route ID on DHT for repo {}",
            hex::encode(self.id().opaque().ref_value())
        );

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
            info!(
                "Retrieved route ID blob for writable repo {}",
                hex::encode(self.id().opaque().ref_value())
            );
            return Ok(blob);
        }

        info!(
            "Getting route ID blob from DHT for repo {} subkey {}",
            hex::encode(self.dht_record.key().opaque().ref_value()),
            ROUTE_SUBKEY
        );

        let value = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), ROUTE_SUBKEY, true)
            .await?;

        let value = match value {
            Some(v) => {
                info!(
                    "Route ID blob found in DHT for repo {}",
                    hex::encode(self.id().opaque().ref_value())
                );
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
                Some(SetDHTValueOptions::default()),
            )
            .await
            .map_err(|e| anyhow!("Failed to store collection blob in DHT: {e}"))?;

        Ok(())
    }

    pub async fn get_hash_from_dht(&self) -> Result<Hash> {
        let repo_id = hex::encode(self.dht_record.key().opaque().ref_value());
        info!(
            "Getting hash from DHT for repo {} subkey {}",
            repo_id, HASH_SUBKEY
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
                    let hash = hash_from_dht_bytes(v.data())?;

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
                            "Unable to get DHT value for repo root hash after {max_retries} retries. \
                             Repo may be empty or hash not yet published to DHT."
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

    /// Upload a raw Iroh blob and publish its hash to DHT.
    ///
    /// This intentionally stores the file bytes as-is. Use [`Repo::upload`] for
    /// encrypted, named files that are tracked in the repo collection.
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
                        hex::encode(self.id().opaque().ref_value()),
                        e
                    );
                    // Error if we're trying to create a collection in a read-only repo
                    return Err(anyhow::Error::msg(format!(
                        "Collection not found and cannot create in read-only repo. Error: {e}"
                    )));
                }
            }
        }
        // If the repo is writable, check if the collection exists
        // Use repo ID as namespace to guarantee uniqueness across groups
        let collection_name = self.collection_name();

        // Try new naming scheme first
        match self.iroh_blobs.collection_hash(&collection_name).await {
            Ok(collection_hash) => {
                // Collection exists with new naming, return the hash
                info!(
                    "Collection found for {}: {}",
                    collection_name,
                    collection_hash.to_hex()
                );
                Ok(collection_hash)
            }
            Err(_) => {
                // Migration: check if old name exists
                let legacy_name = self.get_name().await.ok();
                if let Some(old_name) = legacy_name {
                    if let Ok(old_hash) = self.iroh_blobs.collection_hash(&old_name).await {
                        info!(
                            "Migrating collection from '{}' to '{}'",
                            old_name, collection_name
                        );
                        // Note: Can't rename in Iroh, but we use the old hash
                        // Just update DHT with the existing hash
                        if let Err(e) = self.update_hash_on_dht(&old_hash).await {
                            warn!("Failed to update hash on DHT during migration: {}", e);
                        }
                        return Ok(old_hash);
                    }
                }

                // Create new collection with namespaced name
                info!("Creating new collection with name {}", collection_name);
                let new_hash = match self.iroh_blobs.create_collection(&collection_name).await {
                    Ok(hash) => {
                        info!("New collection created with hash: {}", hash.to_hex());
                        hash
                    }
                    Err(e) => {
                        error!("Failed to create collection: {e:?}");
                        return Err(anyhow!(
                            "Failed to create collection {collection_name}: {e}"
                        ));
                    }
                };

                // Update the DHT with the new collection hash
                if let Err(e) = self.update_collection_on_dht().await {
                    error!("Failed to update DHT with new collection hash: {e:?}");
                    return Err(anyhow!(
                        "Failed to update DHT with collection hash for {collection_name}: {e}"
                    ));
                }

                info!(
                    "DHT updated with new collection hash: {}",
                    new_hash.to_hex()
                );
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
        let collection_name = self.collection_name();
        self.iroh_blobs
            .persist_collection_with_name(&collection_name, &deleted_hash)
            .await?;

        // Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;

        Ok(deleted_hash)
    }

    // Method to get the collection's hash
    async fn get_collection_hash(&self) -> Result<Hash> {
        let collection_name = self.collection_name();

        self.iroh_blobs.collection_hash(&collection_name).await
    }

    /// Encrypt file data with group's encryption key
    /// Format: [MAGIC(4)] [VERSION(1)] [NONCE(24)] [ENCRYPTED_DATA]
    fn encrypt_file_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let veilid = self.get_veilid_api();
        let crypto = veilid.crypto()?;
        let crypto_system = crypto
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

        let nonce = crypto_system.random_nonce();
        let encrypted_chunk = crypto_system
            .encrypt_aead(data, &nonce, &self.get_encryption_key(), None)
            .map_err(|e| anyhow!("Failed to encrypt file data: {e}"))?;

        // Build encrypted file: MAGIC + VERSION + NONCE + ENCRYPTED_DATA
        let mut buffer = Vec::with_capacity(4 + 1 + nonce.bytes().len() + encrypted_chunk.len());
        buffer.extend_from_slice(ENCRYPTED_FILE_MAGIC);
        buffer.push(ENCRYPTED_FILE_VERSION);
        buffer.extend_from_slice(&nonce.bytes());
        buffer.extend_from_slice(&encrypted_chunk);

        Ok(buffer)
    }

    /// Decrypt file data, auto-detecting encrypted vs plaintext
    /// Returns (decrypted_data, was_encrypted)
    pub fn decrypt_file_data(&self, data: &[u8]) -> Result<(Vec<u8>, bool)> {
        match split_file_data_envelope(data)? {
            FileDataEnvelope::Plaintext(plaintext) => {
                // File is not encrypted (legacy/migration case)
                warn!("File not encrypted, returning plaintext data");
                Ok((plaintext.to_vec(), false))
            }
            FileDataEnvelope::Encrypted { nonce, ciphertext } => {
                let veilid = self.get_veilid_api();
                let crypto = veilid.crypto()?;
                let crypto_system = crypto
                    .get(CRYPTO_KIND_VLD0)
                    .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

                let decrypted = crypto_system
                    .decrypt_aead(ciphertext, &nonce, &self.get_encryption_key(), None)
                    .map_err(|e| anyhow!("Failed to decrypt file data: {e}"))?;

                Ok((decrypted, true))
            }
        }
    }

    /// Upload a named file to the repo collection after wrapping it in the
    /// group encryption envelope (`SAVE` magic, version, nonce, ciphertext).
    pub async fn upload(&self, file_name: &str, data_to_upload: Vec<u8>) -> Result<Hash> {
        self.check_write_permissions()?;

        // Encrypt file data before uploading
        let encrypted_data = self.encrypt_file_data(&data_to_upload)?;
        info!(
            "File encrypted: {} bytes → {} bytes",
            data_to_upload.len(),
            encrypted_data.len()
        );

        // Ensure the collection exists before uploading
        let collection_hash = self.get_or_create_collection().await?;

        // Use the stable collection name (namespaced by repo ID)
        let collection_name = self.collection_name();
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(1);
        tx.send(Ok(Bytes::from(encrypted_data))).await.unwrap();
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
        info!("Updated collection hash: {updated_collection_hash:?}");

        // Step 2: Persist the new collection hash locally
        self.iroh_blobs
            .persist_collection_with_name(collection_name, &updated_collection_hash)
            .await?;
        info!("Collection persisted with new hash: {updated_collection_hash:?}");

        // Step 3: Update the DHT with the new collection hash
        self.update_collection_on_dht().await?;
        info!("DHT updated with new collection hash: {updated_collection_hash:?}");

        Ok(updated_collection_hash)
    }

    // Helper method to check if the repo can write
    fn check_write_permissions(&self) -> Result<()> {
        ensure_write_permissions(self.can_write())
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
        self.secret_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_err(data: &[u8]) -> String {
        match split_file_data_envelope(data) {
            Ok(_) => panic!("expected envelope error"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn hash_from_dht_bytes_rejects_non_hex() {
        let err = hash_from_dht_bytes(b"not hex").expect_err("non-hex hash should fail");
        assert!(err.to_string().contains("Failed to decode hex string"));
    }

    #[test]
    fn hash_from_dht_bytes_rejects_short_hash() {
        let err = hash_from_dht_bytes(b"abcd").expect_err("short hash should fail");
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn hash_from_dht_bytes_accepts_32_byte_hash_hex() {
        let hex_hash = "11".repeat(32);
        let hash = hash_from_dht_bytes(hex_hash.as_bytes()).expect("valid hash should parse");
        assert_eq!(hash.as_bytes(), &[0x11; 32]);
    }

    #[test]
    fn encrypted_file_envelope_accepts_short_save_prefixed_plaintext() {
        match split_file_data_envelope(b"SAVE\x01short").expect("short legacy file should parse") {
            FileDataEnvelope::Plaintext(data) => assert_eq!(data, b"SAVE\x01short"),
            FileDataEnvelope::Encrypted { .. } => {
                panic!("short SAVE-prefixed data must remain plaintext")
            }
        }
    }

    #[test]
    fn encrypted_file_envelope_accepts_header_only_plaintext() {
        let mut payload = Vec::from(&ENCRYPTED_FILE_MAGIC[..]);
        payload.push(ENCRYPTED_FILE_VERSION);
        payload.extend_from_slice(&[0u8; crate::common::AEAD_NONCE_LEN]);

        match split_file_data_envelope(&payload).expect("header-only legacy file should parse") {
            FileDataEnvelope::Plaintext(data) => assert_eq!(data, payload.as_slice()),
            FileDataEnvelope::Encrypted { .. } => {
                panic!("header-only SAVE-prefixed data must remain plaintext")
            }
        }
    }

    #[test]
    fn encrypted_file_envelope_rejects_unsupported_version_with_ciphertext() {
        let mut payload = Vec::from(&ENCRYPTED_FILE_MAGIC[..]);
        payload.push(0x02);
        payload.extend_from_slice(&[0u8; crate::common::AEAD_NONCE_LEN]);
        payload.push(1);

        let err = envelope_err(&payload);
        assert!(err.contains("Unsupported encryption version"));
    }

    #[test]
    fn encrypted_file_envelope_accepts_legacy_plaintext() {
        match split_file_data_envelope(b"legacy plaintext").expect("plaintext should parse") {
            FileDataEnvelope::Plaintext(data) => assert_eq!(data, b"legacy plaintext"),
            FileDataEnvelope::Encrypted { .. } => panic!("plaintext must not be encrypted"),
        }
    }

    #[test]
    fn write_permission_guard_rejects_read_only_repo() {
        let err = ensure_write_permissions(false).expect_err("read-only repo should fail");
        assert!(err.to_string().contains("write permissions"));
    }

    #[test]
    fn write_permission_guard_accepts_writable_repo() {
        ensure_write_permissions(true).expect("writable repo should pass");
    }
}
