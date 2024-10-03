use eyre::{anyhow, Error, Result};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, RoutingContext, SharedSecret,
    TypedKey,
};

use crate::common::DHTEntity;
use crate::repo::Repo;

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
