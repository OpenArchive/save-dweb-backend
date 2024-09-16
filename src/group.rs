use serde::{Serialize, Deserialize};
use eyre::{Result, Error, anyhow};
use std::sync::Arc;
use veilid_core::{
    CryptoKey, DHTRecordDescriptor, CryptoTyped, CryptoSystemVLD0, RoutingContext, SharedSecret, TypedKey
};

use crate::common::DHTEntity;
use crate::repo::Repo;

#[derive(Clone)]
pub struct Group {
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
    pub repos: Vec<Repo>,
}

impl Group {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            routing_context,
            crypto_system,
            repos: Vec::new(), 
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
