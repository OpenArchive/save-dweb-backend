use serde::{Serialize, Deserialize};
use anyhow::{Result, Error, anyhow};
use std::path::PathBuf;
use std::any::Any;
use iroh_blobs::Hash;
use std::sync::Arc;
use veilid_core::{
    CryptoKey, DHTRecordDescriptor, CryptoTyped, CryptoSystemVLD0, RoutingContext, SharedSecret, TypedKey, ProtectedStore
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use crate::common::{ DHTEntity, DHTRecordInfo };
use crate::repo::Repo;

#[derive(Clone)]
pub struct Group {
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
    pub repos: Vec<Repo>,
    pub iroh_blobs: Option<VeilidIrohBlobs>,
}

impl Group {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
        iroh_blobs: Option<VeilidIrohBlobs>,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            routing_context,
            crypto_system,
            repos: Vec::new(), 
            iroh_blobs,
        }
    }

    pub fn id(&self) -> CryptoKey {
        self.dht_record.key().value.clone()
    }

    pub fn owner_key(&self) -> CryptoKey {
        self.dht_record.owner().clone()
    }

    pub fn owner_secret(&self) -> Option<CryptoKey> {
        self.dht_record.owner_secret().cloned()
    }
    
    pub async fn add_repo(&mut self, repo: Repo) -> Result<()> {
        self.repos.push(repo);
        Ok(())
    }

    pub async fn list_repos(&self) -> Vec<CryptoKey> {
        self.repos.iter().map(|repo| repo.get_id()).collect()
    }

    pub async fn get_repo_name(&self, repo_key: CryptoKey) -> Result<String> {
        if let Some(repo) = self.repos.iter().find(|repo| repo.get_id() == repo_key) {
            repo.get_name().await
        } else {
            Err(anyhow!("Repo not found"))
        }
    }

    pub async fn upload_blob(&self, file_path: PathBuf, protected_store: &ProtectedStore) -> Result<Hash> {
        if let Some(iroh_blobs) = &self.iroh_blobs {
            // Upload the file and get the hash
            let hash = iroh_blobs.upload_from_path(file_path).await?;
            
            // Convert hash to hex for DHT storage
            let root_hash_hex = hash.to_hex();

            // Set the root hash in the DHT record
            self.routing_context.set_dht_value(
                self.dht_record.key().clone(), 
                1,                              
                root_hash_hex.clone().into(),           
                None                            
            )
            .await
            .map_err(|e| anyhow!("Failed to store collection blob in DHT: {}", e))?;

            // Create an instance of DHTRecordInfo
            let dht_record_info = DHTRecordInfo {
                id: self.get_id().clone(),             
                dht_key: self.dht_record.key().value, 
                cid: Some(root_hash_hex),           
            };

            // Store the DHT record info and CID in the Veilid protected store
            dht_record_info.store(protected_store).await.map_err(|e| anyhow!("Failed to store DHT record info: {}", e))?;

    
            Ok(hash)
        } else {
            Err(anyhow!("iroh_blobs not initialized"))
        }
    }

}

impl DHTEntity for Group {
    fn get_id(&self) -> CryptoKey {
        self.id().clone()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.encryption_key.clone()
    }

    fn get_routing_context(&self) -> Arc<RoutingContext> {
        self.routing_context.clone()
    }

    fn get_crypto_system(&self) -> CryptoSystemVLD0 {
        self.crypto_system.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.owner_secret()
    }

    fn get_route_id_blob(&self) -> Vec<u8> {
        self.iroh_blobs.as_ref().expect("iroh_blobs not initialized").route_id_blob()
    }
}
