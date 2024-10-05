use crate::common::DHTEntity;
use crate::repo::Repo;
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use hex::ToHex;
use iroh_blobs::Hash;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, ProtectedStore, RoutingContext,
    SharedSecret, TypedKey,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

pub const PROTOCOL_SCHEME: &str = "save+dweb:";
pub const URL_DHT_KEY: &str = "dht";
pub const URL_ENCRYPTION_KEY: &str = "enc";
pub const URL_PUBLIC_KEY: &str = "pk";
pub const URL_SECRET_KEY: &str = "sk";

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

    pub fn add_repo(&mut self, repo: Repo) -> Result<()> {
        self.repos.push(repo);
        Ok(())
    }

    pub fn list_repos(&self) -> Vec<CryptoKey> {
        self.repos.iter().map(|repo| repo.get_id()).collect()
    }

    pub fn get_own_repo(&self) -> Option<&Repo> {
        for repo in self.repos.iter() {
            if repo.can_write() {
                return Some(&repo);
            }
        }
        None
    }

    pub fn list_peer_repos(&self) -> Vec<&Repo> {
        self.repos.iter().filter(|repo| !repo.can_write()).collect()
    }

    pub async fn download_hash_from_peers(&self, hash: &Hash) -> Result<()> {
        let iroh_blobs = match self.iroh_blobs.as_ref() {
            Some(iroh_blobs) => iroh_blobs,
            None => return Err(anyhow!("Iroh not initialized")),
        };

        // Ask peers to download in random order
        let mut rng = thread_rng();
        let mut repos = self.list_peer_repos();
        repos.shuffle(&mut rng);

        for repo in repos.iter() {
            if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                // It's faster to try and fail, than to ask then try
                if let Ok(_) = iroh_blobs.download_file_from(route_id_blob, hash).await {
                    return Ok(());
                }
            }
        }

        Err(anyhow!("Unable to download from any peer"))
    }

    pub async fn peers_have_hash(&self, hash: &Hash) -> Result<bool> {
        let iroh_blobs = match self.iroh_blobs.as_ref() {
            Some(iroh_blobs) => iroh_blobs,
            None => return Err(anyhow!("Iroh not initialized")),
        };

        for repo in self.list_peer_repos().iter() {
            if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                if let Ok(has) = iroh_blobs.ask_hash(route_id_blob, *hash).await {
                    if has {
                        return Ok(true);
                    }
                }
            }
        }

        return Ok(false);
    }

    pub async fn has_hash(&self, hash: &Hash) -> Result<bool> {
        let iroh_blobs = match self.iroh_blobs.as_ref() {
            Some(iroh_blobs) => iroh_blobs,
            None => return Err(anyhow!("Iroh not initialized")),
        };

        let has = iroh_blobs.has_hash(hash).await;

        Ok(has)
    }

    pub async fn get_stream_from_hash(
        &self,
        hash: &Hash,
    ) -> Result<mpsc::Receiver<std::io::Result<Bytes>>> {
        let iroh_blobs = match self.iroh_blobs.as_ref() {
            Some(iroh_blobs) => iroh_blobs,
            None => return Err(anyhow!("Iroh not initialized")),
        };

        if self.has_hash(hash).await? {
            self.download_hash_from_peers(hash).await?
        }

        let receiver = iroh_blobs.read_file(*hash).await.unwrap();

        Ok(receiver)
    }

    pub async fn get_repo_name(&self, repo_key: CryptoKey) -> Result<String> {
        if let Some(repo) = self.repos.iter().find(|repo| repo.get_id() == repo_key) {
            repo.get_name().await
        } else {
            Err(anyhow!("Repo not found"))
        }
    }

    pub fn get_url(&self) -> String {
        let mut url = Url::parse(format!("{0}:?", PROTOCOL_SCHEME).as_str()).unwrap();

        url.query_pairs_mut()
            .append_pair(URL_DHT_KEY, self.id().encode_hex::<String>().as_str())
            .append_pair(
                URL_ENCRYPTION_KEY,
                self.get_encryption_key().encode_hex::<String>().as_str(),
            )
            .append_pair(
                URL_PUBLIC_KEY,
                self.owner_key().encode_hex::<String>().as_str(),
            )
            .append_pair(
                URL_SECRET_KEY,
                self.owner_secret().unwrap().encode_hex::<String>().as_str(),
            );

        url.to_string()
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
}
