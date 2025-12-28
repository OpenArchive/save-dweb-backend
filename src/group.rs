use crate::common::CommonKeypair;
use crate::repo::Repo;
use crate::{common::DHTEntity, repo};
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use hex::ToHex;
use iroh::net::key::SecretKey as IrohSecretKey;
use iroh_blobs::Hash;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use std::path::PathBuf;
use std::result;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use url::Url;
use veilid_core::{
    PublicKey, SecretKey, RecordKey, CryptoTyped, DHTRecordDescriptor, DHTReportScope, DHTSchema,
    KeyPair, ProtectedStore, RoutingContext, SharedSecret, TypedRecordKey, ValueSubkeyRangeSet,
    VeilidAPI, VeilidUpdate, CRYPTO_KEY_LENGTH, CRYPTO_KIND_VLD0,
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
    pub repos: Arc<Mutex<HashMap<RecordKey, Repo>>>,
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
            repos: Arc::new(Mutex::new(HashMap::new())),
            veilid,
            iroh_blobs,
        }
    }

    pub fn id(&self) -> RecordKey {
        self.dht_record.key().value
    }

    pub fn owner_key(&self) -> PublicKey {
        *self.dht_record.owner()
    }

    pub fn owner_secret(&self) -> Option<SecretKey> {
        self.dht_record.owner_secret().copied()
    }

    async fn add_repo(&mut self, repo: Repo) -> Result<()> {
        let id = repo.id();
        self.repos.lock().await.insert(id, repo);
        Ok(())
    }

    pub async fn get_repo(&self, id: &RecordKey) -> Result<Repo> {
        self.repos
            .lock()
            .await
            .get(id)
            .ok_or_else(|| anyhow!("Repo not loaded"))
            .cloned()
    }

    pub async fn has_repo(&self, id: &RecordKey) -> bool {
        self.repos.lock().await.contains_key(id)
    }

    pub async fn list_repos(&self) -> Vec<RecordKey> {
        self.repos
            .lock()
            .await
            .values()
            .map(|repo| repo.get_id())
            .collect()
    }

    pub async fn get_own_repo(&self) -> Option<Repo> {
        self.repos
            .lock()
            .await
            .values()
            .find(|repo| repo.can_write())
            .cloned()
    }

    pub async fn list_peer_repos(&self) -> Vec<Repo> {
        self.repos
            .lock()
            .await
            .values()
            .filter(|repo| !repo.can_write())
            .cloned()
            .collect()
    }

    pub async fn download_hash_from_peers(&self, hash: &Hash) -> Result<()> {
        // Ask peers to download in random order
        let mut rng = thread_rng();
        let mut repos = self.list_peer_repos().await;
        repos.shuffle(&mut rng);

        if repos.is_empty() {
            return Err(anyhow!("Cannot download hash. No other peers found"));
        }

        // Retry configuration
        const MAX_RETRIES: u32 = 3;
        const INITIAL_DELAY_MS: u64 = 500;
        const MAX_DELAY_MS: u64 = 2000;

        for attempt in 0..MAX_RETRIES {
            for repo in repos.iter() {
                info!(
                    "Attempt {}: Trying to download hash {} from peer {}",
                    attempt + 1,
                    hash.to_hex(),
                    repo.id().encode_hex::<String>()
                );
                
                if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                    // It's faster to try and fail, than to ask then try
                    let result = self
                        .iroh_blobs
                        .download_file_from(route_id_blob, hash)
                        .await;
                    
                    if result.is_ok() {
                        info!("Successfully downloaded hash {} from peer {}", 
                            hash.to_hex(),
                            repo.id().encode_hex::<String>()
                        );
                        return Ok(());
                    } else {
                        warn!(
                            "Unable to download from peer {}: {}",
                            repo.id().encode_hex::<String>(),
                            result.unwrap_err()
                        );
                    }
                } else {
                    warn!(
                        "Unable to get route ID blob for peer {}",
                        repo.id().encode_hex::<String>()
                    );
                }
            }

            // If we've exhausted all peers and there are retries left, wait before retrying
            if attempt < MAX_RETRIES - 1 {
                let delay_ms = std::cmp::min(
                    INITIAL_DELAY_MS * (1 << attempt), // Exponential backoff
                    MAX_DELAY_MS
                );
                info!(
                    "All peers failed for hash {}, retrying in {}ms (attempt {}/{})",
                    hash.to_hex(),
                    delay_ms,
                    attempt + 2,
                    MAX_RETRIES
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                
                // Refresh peer list in case new peers joined
                let mut refreshed_repos = self.list_peer_repos().await;
                if !refreshed_repos.is_empty() {
                    refreshed_repos.shuffle(&mut rng);
                    repos = refreshed_repos;
                }
            }
        }

        Err(anyhow!(
            "Unable to download hash {} from any peer after {} attempts",
            hash.to_hex(),
            MAX_RETRIES
        ))
    }

    pub async fn peers_have_hash(&self, hash: &Hash) -> Result<bool> {
        for repo in self.list_peer_repos().await.iter() {
            if let Ok(route_id_blob) = repo.get_route_id_blob().await {
                println!("Asking {} from {} via {:?}", hash, repo.id(), route_id_blob);
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
        if !self.has_hash(hash).await? {
            self.download_hash_from_peers(hash).await?
        }

        let receiver = self.iroh_blobs.read_file(*hash).await.unwrap();

        Ok(receiver)
    }

    pub async fn get_repo_name(&self, repo_key: RecordKey) -> Result<String> {
        if let Some(repo) = self.repos.lock().await.get(&repo_key) {
            repo.get_name().await
        } else {
            Err(anyhow!("Repo not found"))
        }
    }

    pub fn get_url(&self) -> String {
        let mut url = Url::parse(format!("{PROTOCOL_SCHEME}:?").as_str()).unwrap();

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

        let record_key = dht_record.key().clone();

        let report = self
            .routing_context
            .inspect_dht_record(record_key, Some(range), scope)
            .await?;

        let size = report.network_seqs().len();

        let mut count = 0;

        while count < (size - 1) {
            let value = self
                .routing_context
                .get_dht_value(record_key, (count + 1).try_into()?, true)
                .await?;
            if value.is_some() {
                count += 1;
            } else {
                return Ok(count);
            }
        }

        Ok(count)
    }

    pub async fn advertise_own_repo(&self) -> Result<()> {
        let repo = self
            .get_own_repo()
            .await
            .ok_or_else(|| anyhow!("No own repo found for group"))?;

        let repo_key = repo.id().bytes.to_vec();

        let count = self.dht_repo_count().await? + 1;

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

    pub async fn load_repo_from_network(
        &mut self,
        repo_id: TypedRecordKey,
    ) -> Result<Repo, anyhow::Error> {
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

        let veilid = self.get_veilid_api();
        let mut dht_record: Option<DHTRecordDescriptor> = None;
        let mut retries = 6;

        while retries > 0 {
            retries -= 1;
            let dht_record_result = self
                .routing_context
                .open_dht_record(repo_id.clone(), keypair.clone())
                .await;

            match dht_record_result {
                Ok(record) => {
                    dht_record = Some(record);
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "Failed to open DHT record: {e}. Retries left: {retries}"
                    );
                    if retries == 0 {
                        return Err(anyhow!(
                            "Unable to open DHT record, reached max retries: {}",
                            e
                        ));
                    }
                }
            }

            // Add a delay before retrying (wit exponential backoff)
            tokio::time::sleep(std::time::Duration::from_millis(100 * (7 - retries) as u64)).await;
        }

        // Ensure that `dht_record` is set before proceeding
        let dht_record = dht_record.ok_or_else(|| anyhow!("DHT record retrieval failed"))?;

        let repo = Repo {
            dht_record,
            encryption_key: self.encryption_key.clone(),
            secret_key: None,
            routing_context: self.routing_context.clone(),
            veilid: veilid.clone(),
            iroh_blobs: self.iroh_blobs.clone(),
        };

        self.add_repo(repo.clone()).await?;

        Ok(repo)
    }

    async fn load_repo_from_dht(&mut self, subkey: u32) -> Result<TypedRecordKey> {
        let repo_id_raw = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), subkey, true)
            .await?
            .ok_or_else(|| anyhow!("Unable to load repo ID from DHT"))?;

        let mut repo_id_buffer: [u8; CRYPTO_KEY_LENGTH] = [0; CRYPTO_KEY_LENGTH];

        // Validate the length before copying
        if repo_id_raw.data().len() != repo_id_buffer.len() {
            return Err(anyhow!(
                "Slice length mismatch: expected {}, got {}",
                repo_id_buffer.len(),
                repo_id_raw.data().len()
            ));
        }

        repo_id_buffer.copy_from_slice(repo_id_raw.data());

        let repo_id = TypedRecordKey::new(CRYPTO_KIND_VLD0, RecordKey::new(repo_id_buffer));

        if self.repos.lock().await.contains_key(&repo_id.value) {
            return Ok(repo_id);
        }
        self.load_repo_from_network(repo_id).await?;

        Ok(repo_id)
    }

    pub async fn load_repos_from_dht(&mut self) -> Result<()> {
        let count = self.dht_repo_count().await?;

        let mut i = 1;
        while i <= count {
            println!("Loading from DHT {i}");
            if let Err(e) = self.load_repo_from_dht(i.try_into()?).await {
                eprintln!("Warning: Failed to load repo {i} from DHT: {e:?}");
            }
            i += 1;
        }

        Ok(())
    }

    pub async fn try_load_repo_from_disk(&mut self) -> bool {
        if let Err(err) = self.load_repo_from_disk().await {
            eprintln!("Unable to load own repo from disk {err}");
            false
        } else {
            true
        }
    }

    pub async fn load_repo_from_disk(&mut self) -> Result<Repo> {
        let protected_store = self.veilid.protected_store().unwrap();

        let mut group_repo_key = self.id().to_string();
        group_repo_key.push_str("-repo");

        let key_bytes = protected_store
            .load_user_secret(group_repo_key)
            .map_err(|err| anyhow!("Unable to load repo from disk"))?
            .ok_or_else(|| anyhow!("No repo exists on disk for this group"))?;

        let mut id_bytes: [u8; CRYPTO_KEY_LENGTH] = [0; CRYPTO_KEY_LENGTH];
        id_bytes.copy_from_slice(&key_bytes);
        let repo_id = TypedRecordKey::new(CRYPTO_KIND_VLD0, RecordKey::new(id_bytes));

        let keypair = self.get_repo_keypair(repo_id).await?;

        let dht_record = self
            .routing_context
            .open_dht_record(
                repo_id.clone(),
                Some(KeyPair::new(
                    keypair.public_key,
                    keypair.secret_key.unwrap(),
                )),
            )
            .await?;

        let secret_key = keypair.secret_key;

        let repo = Repo::new(
            dht_record,
            self.encryption_key.clone(),
            secret_key,
            self.routing_context.clone(),
            self.veilid.clone(),
            self.iroh_blobs.clone(),
        );
        repo.update_route_on_dht().await?;

        self.add_repo(repo.clone()).await?;

        Ok(repo)
    }

    pub async fn create_repo(&mut self) -> Result<Repo, anyhow::Error> {
        if self.get_own_repo().await.is_some() {
            return Err(anyhow!("Own repo already created for group"));
        }

        // Create a new DHT record for the repo
        let schema = DHTSchema::dflt(3)?;
        let kind = Some(CRYPTO_KIND_VLD0);
        let repo_dht_record = self
            .routing_context
            .create_dht_record(schema, None, kind)
            .await?;

        // Identify the repo with the DHT record's key
        let repo_id = repo_dht_record.key().clone();

        // Use the group's encryption key for the repo
        let encryption_key = self.get_encryption_key().clone();

        let repo = Repo::new(
            repo_dht_record.clone(),
            encryption_key,
            self.get_secret_key(),
            self.routing_context.clone(),
            self.veilid.clone(),
            self.iroh_blobs.clone(),
        );

        // This should happen every time the route ID changes
        repo.update_route_on_dht().await?;

        let protected_store = self.veilid.protected_store().unwrap();

        let keypair = CommonKeypair {
            id: repo.id(),
            public_key: repo_dht_record.owner().clone(),
            secret_key: repo_dht_record.owner_secret().copied(),
            encryption_key: encryption_key.clone(),
        };

        keypair
            .store_keypair(&protected_store)
            .await
            .map_err(|e| anyhow!(e))?;

        let mut group_repo_key = self.id().to_string();
        group_repo_key.push_str("-repo");
        let key_bytes = repo.id().bytes;
        protected_store
            .save_user_secret(group_repo_key, &key_bytes)
            .map_err(|e| anyhow!("Unable to store repo id for group: {}", e))?;

        self.add_repo(repo).await?;

        self.advertise_own_repo().await?;

        // Ensure hash is published to DHT immediately for read-only members
        if let Some(owned_repo) = self.get_own_repo().await {
            // update_collection_on_dht will create the collection if it doesn't exist
            // and publish its hash to the DHT
            if let Err(e) = owned_repo.update_collection_on_dht().await {
                warn!("Failed to update hash on DHT immediately: {}", e);
                // Don't fail repo creation, but log the warning
            }
        }

        self.get_own_repo()
            .await
            .ok_or_else(|| anyhow!("Unexpected error, created repo not persisted"))
    }

    async fn get_repo_keypair(&self, repo_id: TypedRecordKey) -> Result<CommonKeypair> {
        let protected_store = self.veilid.protected_store()?;

        // Load keypair using the repo ID
        CommonKeypair::load_keypair(&protected_store, &repo_id.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair for repo_id: {:?}", repo_id))
    }

    pub async fn watch_changes<F, Fut>(&self, on_change: F) -> Result<()>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let repo_count = self.dht_repo_count().await?;
        let range = if repo_count > 0 {
            ValueSubkeyRangeSet::single_range(0, repo_count as u32 - 1)
        } else {
            ValueSubkeyRangeSet::full()
        };

        let expiration_duration = 600_000_000;
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64 + expiration_duration;
        let count = 0;

        // Clone necessary data for the async block
        let routing_context = self.routing_context.clone();
        let dht_record_key = self.dht_record.key().clone();

        // Spawn a task that uses only owned data
        tokio::spawn(async move {
            match routing_context
                .watch_dht_values(
                    dht_record_key.clone(),
                    Some(range.clone()),
                    None,
                    None,
                )
                .await
            {
                Ok(_) => {
                    println!(
                        "DHT watch successfully set on record key {dht_record_key:?}"
                    );

                    loop {
                        if let Ok(change) = routing_context
                            .watch_dht_values(
                                dht_record_key.clone(),
                                Some(range.clone()),
                                None,
                                None,
                            )
                            .await
                        {
                            if change {
                                if let Err(e) = on_change().await {
                                    eprintln!("Failed to re-download files: {e:?}");
                                }
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to set DHT watch: {e:?}"),
            }
        });

        Ok(())
    }
}

impl DHTEntity for Group {
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
        self.owner_secret()
    }
}
