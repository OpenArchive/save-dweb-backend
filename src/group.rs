use crate::common::CommonKeypair;
use crate::repo::Repo;
use crate::{common::DHTEntity, repo};
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use hex::ToHex;
use iroh::net::key::SecretKey;
use iroh_blobs::Hash;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use url::Url;
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, DHTReportScope, DHTSchema,
    KeyPair, ProtectedStore, RoutingContext, SharedSecret, TypedKey, ValueSubkeyRangeSet,
    VeilidAPI, CRYPTO_KEY_LENGTH, CRYPTO_KIND_VLD0,
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
    pub routing_context: RoutingContext,
    pub repos: HashMap<CryptoKey, Box<Repo>>,
    pub veilid: VeilidAPI,
    pub iroh_blobs: VeilidIrohBlobs,
}

impl Group {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        routing_context: RoutingContext,
        veilid: VeilidAPI,
        iroh_blobs: VeilidIrohBlobs,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            routing_context,
            repos: HashMap::new(),
            veilid,
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

    fn add_repo(&mut self, repo: Repo) -> Result<&Repo, anyhow::Error> { 
        let id = repo.id();
        let repo = Box::new(repo);
        self.repos.insert(id, repo);
        Ok(self.repos.get(&id).unwrap().as_ref())
    }

    pub fn get_repo(&self, id: &CryptoKey) -> Result<&Repo> { 
        self.repos.get(id).map(|repo| &**repo).ok_or_else(|| anyhow!("Repo not loaded"))
    }

    pub fn has_repo(&self, id: &CryptoKey) -> bool {
        self.repos.contains_key(id)
    }

    pub fn list_repos(&self) -> Vec<CryptoKey> {
        self.repos.values().map(|repo| repo.get_id()).collect()
    }

    pub fn get_own_repo(&self) -> Option<&Repo> {
        self.repos.values().find(|repo| repo.can_write()).map(|v| &**v)
    }

    pub fn list_peer_repos(&self) -> Vec<&Repo> { 
        self.repos
            .values()
            .filter(|repo| !repo.can_write())
            .map(|v| &**v)  // Dereference the Box to get &Repo
            .collect::<Vec<&Repo>>()
    }

    pub async fn download_hash_from_peers(&self, hash: &Hash) -> Result<()> {
        // Ask peers to download in random order
        let mut rng = thread_rng();
        let mut repos = self.list_peer_repos();
        repos.shuffle(&mut rng);

        for repo in repos.iter() {
            if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                // It's faster to try and fail, than to ask then try
                if (self
                    .iroh_blobs
                    .download_file_from(route_id_blob, hash)
                    .await)
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        Err(anyhow!("Unable to download from any peer"))
    }

    pub async fn peers_have_hash(&self, hash: &Hash) -> Result<bool> {
        for repo in self.list_peer_repos().iter() {
            println!("Askinng {} from {}", hash, repo.id());
            if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                if let Ok(has) = self.iroh_blobs.ask_hash(route_id_blob, *hash).await {
                    if has {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    pub async fn has_hash(&self, hash: &Hash) -> Result<bool> {
        let has = self.iroh_blobs.has_hash(hash).await;

        Ok(has)
    }

    pub async fn get_stream_from_hash(
        &self,
        hash: &Hash,
    ) -> Result<mpsc::Receiver<std::io::Result<Bytes>>> {
        if self.has_hash(hash).await? {
            self.download_hash_from_peers(hash).await?
        }

        let receiver = self.iroh_blobs.read_file(*hash).await.unwrap();

        Ok(receiver)
    }

    pub async fn get_repo_name(&self, repo_key: CryptoKey) -> Result<String> {
        if let Some(repo) = self.repos.get(&repo_key) {
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

    async fn dht_repo_count(&self) -> Result<usize> {
        let dht_record = &self.dht_record;
        let range = ValueSubkeyRangeSet::full();
        let scope = DHTReportScope::UpdateGet;

        let report = self
            .routing_context
            .inspect_dht_record(dht_record.key().clone(), range, scope)
            .await?;

        let count = report.network_seqs().len();

        Ok(count)
    }

    pub async fn advertise_own_repo(&self) -> Result<()> {
        let repo = self
            .get_own_repo()
            .ok_or_else(|| anyhow!("No own repo found for group"))?;

        let repo_key = repo.id().to_vec();

        let count = self.dht_repo_count().await?;

        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                count.try_into()?,
                repo_key,
                None,
            )
            .await?;

        Ok(())
    }

    pub async fn load_repo_from_network(&mut self, repo_id: TypedKey) -> Result<&Repo, anyhow::Error> {
        // TODO: Load keypair from DHT
        //        let protected_store = self.protected_store().unwrap();
        // Load keypair using the repo ID
        // let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, &repo_id.value)
        //    .await
        //     .map_err(|_| anyhow!("Failed to load keypair for repo_id: {:?}", repo_id))?;
        // Some(KeyPair::new(
        //             owner_key.clone(),
        //             retrieved_keypair.secret_key.clone().unwrap(),
        //         ))
        let keypair = None;

        let dht_record = self
            .routing_context
            .open_dht_record(repo_id.clone(), keypair)
            .await?;

        let repo = Repo {
            dht_record,
            encryption_key: self.encryption_key.clone(),
            secret_key: None,
            routing_context: self.routing_context.clone(),
            crypto_system: self.get_crypto_system(),
            iroh_blobs: self.iroh_blobs.clone(),
        };

        self.add_repo(repo)
    }

    async fn load_repo_from_dht(&mut self, subkey: u32) -> Result<CryptoTyped<CryptoKey>> {
        let repo_id_raw = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), subkey, false)
            .await?
            .ok_or_else(|| anyhow!("Unable to load repo ID from DHT"))?;

        let mut repo_id_buffer: [u8; CRYPTO_KEY_LENGTH] = [0; CRYPTO_KEY_LENGTH];

        repo_id_buffer.copy_from_slice(repo_id_raw.data());

        let repo_id = TypedKey::new(CRYPTO_KIND_VLD0, CryptoKey::from(repo_id_buffer));

        self.load_repo_from_network(repo_id).await?;

        Ok(repo_id)
    }

    pub async fn load_repos_from_dht(&mut self) -> Result<()> {
        let count = self.dht_repo_count().await?;

        let mut i = 1;
        while i < count {
            self.load_repo_from_dht(i.try_into()?).await?;
            i += 1;
        }

        Ok(())
    }

    pub async fn load_repo_from_disk(&mut self) -> Result<&Repo, anyhow::Error> {
        let protected_store = self.veilid.protected_store().unwrap();

        let mut group_repo_key = self.id().to_string();
        group_repo_key.push_str("-repo");

        let key_bytes = protected_store
            .load_user_secret(group_repo_key)
            .await
            .map_err(|err| anyhow!("Unable to load repo from disk"))?
            .ok_or_else(|| anyhow!("No repo exists on disk for this group"))?;

        let mut id_bytes: [u8; CRYPTO_KEY_LENGTH] = [0; CRYPTO_KEY_LENGTH];
        id_bytes.copy_from_slice(&key_bytes);
        let repo_id = TypedKey::new(CRYPTO_KIND_VLD0, CryptoKey::from(id_bytes));

        let keypair = self.get_repo_keypair(repo_id).await?;

        let dht_record = self
            .routing_context
            .open_dht_record(
                repo_id.clone(),
                Some(KeyPair::new(
                    keypair.public_key.clone(),
                    keypair.secret_key.clone().unwrap(),
                )),
            )
            .await?;

        let secret_key = keypair
            .secret_key
            .map(|key| TypedKey::new(CRYPTO_KIND_VLD0, key));

        let repo = Repo {
            dht_record,
            encryption_key: self.encryption_key.clone(),
            secret_key,
            routing_context: self.routing_context.clone(),
            crypto_system: self.get_crypto_system(),
            iroh_blobs: self.iroh_blobs.clone(),
        };

        self.add_repo(repo)
    }

    pub async fn create_repo(&mut self) -> Result<&Repo, anyhow::Error> {
        if self.get_own_repo().is_some() {
            return Err(anyhow!("Own repo already created for group"));
        }

        // Create a new DHT record for the repo
        let schema = DHTSchema::dflt(3)?;
        let kind = Some(CRYPTO_KIND_VLD0);
        let repo_dht_record = self.routing_context.create_dht_record(schema, kind).await?;

        // Identify the repo with the DHT record's key
        let repo_id = repo_dht_record.key().clone();

        // Use the group's encryption key for the repo
        let encryption_key = self.get_encryption_key().clone();

        // Wrap the secret key in CryptoTyped for storage
        let secret_key_typed =
            CryptoTyped::new(CRYPTO_KIND_VLD0, self.get_secret_key().unwrap().clone());

        let repo = Repo::new(
            repo_dht_record.clone(),
            encryption_key,
            Some(secret_key_typed),
            self.routing_context.clone(),
            self.get_crypto_system(),
            self.iroh_blobs.clone(),
        );

        // This should happen every time the route ID changes
        repo.update_route_on_dht().await?;

        let protected_store = self.veilid.protected_store().unwrap();

        let keypair = CommonKeypair {
            id: repo.id(),
            public_key: repo_dht_record.owner().clone(),
            secret_key: self.get_secret_key(),
            encryption_key: encryption_key.clone(),
        };

        keypair
            .store_keypair(&protected_store)
            .await
            .map_err(|e| anyhow!(e))?;

        let mut group_repo_key = self.id().to_string();
        group_repo_key.push_str("-repo");
        let key_bytes = *repo.id();
        protected_store
            .save_user_secret(group_repo_key, key_bytes.as_slice())
            .await
            .map_err(|e| anyhow!("Unable to store repo id for group: {}", e))?;

        self.add_repo(repo)
    }

    async fn get_repo_keypair(&self, repo_id: TypedKey) -> Result<CommonKeypair> {
        let protected_store = self.veilid.protected_store()?;

        // Load keypair using the repo ID
        CommonKeypair::load_keypair(&protected_store, &repo_id.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair for repo_id: {:?}", repo_id))
    }
}

impl DHTEntity for Group {
    fn get_id(&self) -> CryptoKey {
        self.id().clone()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.encryption_key.clone()
    }

    fn get_routing_context(&self) -> RoutingContext {
        self.routing_context.clone()
    }

    fn get_crypto_system(&self) -> CryptoSystemVLD0 {
        // TODO handle the error?
        CryptoSystemVLD0::new(self.veilid.crypto().unwrap())
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.owner_secret()
    }
}
