use crate::common::CommonKeypair;
use crate::repo::Repo;
use crate::{common::DHTEntity, repo};
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use futures_util::future::join_all;
use hex::ToHex;
use iroh::net::key::SecretKey as IrohSecretKey;
use iroh_blobs::Hash;
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use std::path::PathBuf;
use std::result;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use url::Url;
use veilid_core::{
    DHTRecordDescriptor, DHTReportScope, DHTSchema, KeyPair, ProtectedStore, PublicKey, RecordKey,
    RoutingContext, SecretKey, SetDHTValueOptions, SharedSecret, ValueSubkeyRangeSet, VeilidAPI,
    VeilidAPIError, VeilidUpdate, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

pub const PROTOCOL_SCHEME: &str = "save+dweb:";
pub const URL_DHT_KEY: &str = "dht";
pub const URL_ENCRYPTION_KEY: &str = "enc";
pub const URL_PUBLIC_KEY: &str = "pk";
pub const URL_SECRET_KEY: &str = "sk";
pub const MAX_GROUP_REPOS: u32 = 64;

#[derive(Debug, PartialEq, Eq)]
enum RepoAdvertisementSlot {
    AlreadyPresent(u32),
    Open(u32),
}

#[derive(Debug, PartialEq, Eq)]
enum RepoAdvertisementVerification {
    Verified,
    Missing,
    Collision,
}

fn choose_repo_advertisement_slot<'a, I>(slots: I, repo_key: &[u8]) -> Result<RepoAdvertisementSlot>
where
    I: IntoIterator<Item = (u32, Option<&'a [u8]>)>,
{
    let mut first_open = None;

    for (subkey, value) in slots {
        if !(1..=MAX_GROUP_REPOS).contains(&subkey) {
            continue;
        }

        match value {
            Some(existing) if existing == repo_key => {
                return Ok(RepoAdvertisementSlot::AlreadyPresent(subkey));
            }
            Some(_) => {}
            None if first_open.is_none() => first_open = Some(subkey),
            None => {}
        }
    }

    first_open
        .map(RepoAdvertisementSlot::Open)
        .ok_or_else(|| anyhow!("No free repo advertisement slots in group DHT record"))
}

fn verify_repo_advertisement(
    stored_value: Option<&[u8]>,
    repo_key: &[u8],
) -> RepoAdvertisementVerification {
    match stored_value {
        Some(value) if value == repo_key => RepoAdvertisementVerification::Verified,
        Some(_) => RepoAdvertisementVerification::Collision,
        None => RepoAdvertisementVerification::Missing,
    }
}

fn repo_watch_subkey_bounds() -> (u32, u32) {
    (1, MAX_GROUP_REPOS)
}

fn repo_record_key_from_dht_bytes(data: &[u8]) -> Result<RecordKey> {
    if data.len() == 32 {
        // Legacy (pre-Veilid-0.5.1): raw 32-byte opaque key from old advertise_own_repo.
        // Supports mixed groups where some peers have not yet upgraded.
        let mut arr = [0u8; 32];
        arr.copy_from_slice(data);
        return Ok(RecordKey::new(
            CRYPTO_KIND_VLD0,
            veilid_core::BareRecordKey::new(veilid_core::BareOpaqueRecordKey::from(&arr[..]), None),
        ));
    }

    if let Ok(s) = String::from_utf8(data.to_vec()) {
        let bare_key = veilid_core::BareRecordKey::try_decode(&s)
            .map_err(|e| anyhow!("Failed to decode repo record key: {e}"))?;
        return Ok(RecordKey::new(CRYPTO_KIND_VLD0, bare_key));
    }

    Err(anyhow!(
        "Repo key on DHT is neither legacy 32-byte nor valid UTF-8 encoded key (len={})",
        data.len()
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum RepoWatchUpdate {
    Ignore,
    Changed,
    WatchEnded,
}

#[derive(Clone)]
pub struct Group {
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub routing_context: RoutingContext,
    pub repos: Arc<Mutex<HashMap<String, Repo>>>,
    pub veilid: VeilidAPI,
    pub iroh_blobs: VeilidIrohBlobs,
    update_rx: Arc<Mutex<broadcast::Receiver<VeilidUpdate>>>,
}

impl Group {
    pub fn new(
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        routing_context: RoutingContext,
        veilid: VeilidAPI,
        iroh_blobs: VeilidIrohBlobs,
        update_rx: broadcast::Receiver<VeilidUpdate>,
    ) -> Self {
        Self {
            dht_record,
            encryption_key,
            routing_context,
            repos: Arc::new(Mutex::new(HashMap::new())),
            veilid,
            iroh_blobs,
            update_rx: Arc::new(Mutex::new(update_rx)),
        }
    }

    /// Convert RecordKey to stable cache key (hex-encoded opaque bytes)
    fn repo_cache_key(record_key: &RecordKey) -> String {
        hex::encode(record_key.opaque().ref_value())
    }

    pub fn id(&self) -> RecordKey {
        self.dht_record.key().clone()
    }

    pub fn owner_key(&self) -> PublicKey {
        self.dht_record.owner().clone()
    }

    pub fn owner_secret(&self) -> Option<SecretKey> {
        self.dht_record.owner_secret().clone()
    }

    async fn add_repo(&mut self, repo: Repo) -> Result<()> {
        let id = repo.id();
        let cache_key = Self::repo_cache_key(&id);
        self.repos.lock().await.insert(cache_key, repo);
        Ok(())
    }

    pub async fn get_repo(&self, id: &RecordKey) -> Result<Repo> {
        let cache_key = Self::repo_cache_key(id);
        self.repos
            .lock()
            .await
            .get(&cache_key)
            .ok_or_else(|| anyhow!("Repo not loaded"))
            .cloned()
    }

    pub async fn has_repo(&self, id: &RecordKey) -> bool {
        let cache_key = Self::repo_cache_key(id);
        self.repos.lock().await.contains_key(&cache_key)
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
        self.download_hash_from_peers_with_timeout(hash, None).await
    }

    pub async fn download_hash_from_peers_with_timeout(
        &self,
        hash: &Hash,
        overall_timeout: Option<Duration>,
    ) -> Result<()> {
        // Ask peers to download in random order
        let mut repos = self.list_peer_repos().await;
        repos.shuffle(&mut thread_rng());

        if repos.is_empty() {
            return Err(anyhow!("Cannot download hash. No other peers found"));
        }

        // Retry configuration
        // Veilid route establishment + iroh tunnel setup can be transiently flaky, especially
        // under load in CI or when routes are regenerating. Keep this bounded but resilient.
        // Keep this bounded: higher-level callers (HTTP endpoints/tests) can retry too.
        const MAX_RETRIES: u32 = 5;
        const INITIAL_DELAY_MS: u64 = 500;
        const MAX_DELAY_MS: u64 = 4000;
        const PER_PEER_TIMEOUT_SECS: u64 = 10;
        let per_peer_timeout = Duration::from_secs(PER_PEER_TIMEOUT_SECS);
        let started = Instant::now();
        let overall_timeout_ms = overall_timeout.map(|timeout| timeout.as_millis());
        let remaining_budget = || {
            overall_timeout
                .map(|timeout| timeout.checked_sub(started.elapsed()).unwrap_or_default())
        };
        let timeout_exhausted_error = || {
            anyhow!(
                "Unable to download hash {} from any peer within {}ms overall timeout",
                hash.to_hex(),
                overall_timeout_ms.unwrap_or_default()
            )
        };

        for attempt in 0..MAX_RETRIES {
            for repo in repos.iter() {
                let timeout_budget = match remaining_budget() {
                    Some(remaining) if remaining.is_zero() => return Err(timeout_exhausted_error()),
                    Some(remaining) => std::cmp::min(per_peer_timeout, remaining),
                    None => per_peer_timeout,
                };

                info!(
                    "Attempt {}: Trying to download hash {} from peer {}",
                    attempt + 1,
                    hash.to_hex(),
                    hex::encode(repo.id().opaque().ref_value())
                );

                // It's faster to try and fail, than to ask then try. Keep route lookup inside the
                // timeout too so one peer cannot stall the whole request before downloading starts.
                let result = tokio::time::timeout(timeout_budget, async {
                    let route_id_blob = repo.get_route_id_blob().await?;
                    self.iroh_blobs
                        .download_file_from(route_id_blob, hash)
                        .await
                })
                .await;

                match result {
                    Ok(Ok(())) => {
                        info!(
                            "Successfully downloaded hash {} from peer {}",
                            hash.to_hex(),
                            hex::encode(repo.id().opaque().ref_value())
                        );
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "Unable to download from peer {}: {}",
                            hex::encode(repo.id().opaque().ref_value()),
                            e
                        );
                    }
                    Err(_) => {
                        warn!(
                            "Timed out downloading hash {} from peer {} after {}ms",
                            hash.to_hex(),
                            hex::encode(repo.id().opaque().ref_value()),
                            timeout_budget.as_millis()
                        );
                    }
                }
            }

            // If we've exhausted all peers and there are retries left, wait before retrying
            if attempt < MAX_RETRIES - 1 {
                let delay_ms = std::cmp::min(
                    INITIAL_DELAY_MS * (1 << attempt), // Exponential backoff
                    MAX_DELAY_MS,
                );
                info!(
                    "All peers failed for hash {}, retrying in {}ms (attempt {}/{})",
                    hash.to_hex(),
                    delay_ms,
                    attempt + 2,
                    MAX_RETRIES
                );
                let delay = Duration::from_millis(delay_ms);
                if let Some(remaining) = remaining_budget() {
                    if remaining.is_zero() {
                        return Err(timeout_exhausted_error());
                    }
                    tokio::time::sleep(std::cmp::min(delay, remaining)).await;
                } else {
                    tokio::time::sleep(delay).await;
                }

                // Refresh peer list in case new peers joined
                let mut refreshed_repos = self.list_peer_repos().await;
                if !refreshed_repos.is_empty() {
                    refreshed_repos.shuffle(&mut thread_rng());
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
                info!("Asking {} from {} via {:?}", hash, repo.id(), route_id_blob);
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

        let receiver = self.iroh_blobs.read_file(*hash).await?;

        Ok(receiver)
    }

    pub async fn get_repo_name(&self, repo_key: RecordKey) -> Result<String> {
        let cache_key = Self::repo_cache_key(&repo_key);
        if let Some(repo) = self.repos.lock().await.get(&cache_key) {
            repo.get_name().await
        } else {
            Err(anyhow!("Repo not found"))
        }
    }

    pub fn get_url(&self) -> Result<String> {
        let owner_secret = self
            .owner_secret()
            .ok_or_else(|| anyhow!("Cannot generate URL: no owner secret"))?;
        let mut url = Url::parse(format!("{PROTOCOL_SCHEME}:?").as_str()).unwrap();

        url.query_pairs_mut()
            // Include the record encryption key in the encoded DHT key.
            .append_pair(URL_DHT_KEY, self.id().ref_value().encode().as_str())
            .append_pair(
                URL_ENCRYPTION_KEY,
                hex::encode(self.get_encryption_key().ref_value().bytes()).as_str(),
            )
            .append_pair(
                URL_PUBLIC_KEY,
                hex::encode(self.owner_key().ref_value().bytes()).as_str(),
            )
            .append_pair(
                URL_SECRET_KEY,
                hex::encode(owner_secret.ref_value().bytes()).as_str(),
            );

        Ok(url.to_string())
    }

    async fn load_repo_advertisement_slots(
        &self,
        include_open_slot: bool,
    ) -> Result<Vec<(u32, Option<Vec<u8>>)>> {
        let range = ValueSubkeyRangeSet::single_range(1, MAX_GROUP_REPOS);
        let scope = DHTReportScope::UpdateGet;
        let report = self
            .routing_context
            .inspect_dht_record(self.dht_record.key().clone(), Some(range), scope)
            .await?;

        let mut subkeys_to_read = Vec::new();
        let mut first_open_slot = None;
        for ((subkey, local_seq), network_seq) in report
            .subkeys()
            .iter()
            .zip(report.local_seqs())
            .zip(report.network_seqs())
        {
            if !(1..=MAX_GROUP_REPOS).contains(&subkey) {
                continue;
            }

            if local_seq.is_some() || network_seq.is_some() {
                subkeys_to_read.push(subkey);
            } else if include_open_slot && first_open_slot.is_none() {
                first_open_slot = Some(subkey);
            }
        }

        let record_key = self.dht_record.key().clone();
        let reads = subkeys_to_read.into_iter().map(|subkey| {
            let routing_context = self.routing_context.clone();
            let record_key = record_key.clone();
            async move {
                let value = routing_context
                    .get_dht_value(record_key, subkey, true)
                    .await?
                    .map(|value| value.data().to_vec());
                Ok::<_, anyhow::Error>((subkey, value))
            }
        });

        let mut slots = Vec::with_capacity(MAX_GROUP_REPOS as usize);
        for result in join_all(reads).await {
            slots.push(result?);
        }
        if let Some(subkey) = first_open_slot {
            slots.push((subkey, None));
        }
        slots.sort_by_key(|(subkey, _)| *subkey);

        Ok(slots)
    }

    pub async fn advertise_own_repo(&self) -> Result<()> {
        let repo = self
            .get_own_repo()
            .await
            .ok_or_else(|| anyhow!("No own repo found for group"))?;

        // Store the full encoded record key (includes encryption key) so
        // joining devices can decrypt the repo's DHT values.
        let repo_key = repo.id().ref_value().encode().into_bytes();

        for _attempt in 0..MAX_GROUP_REPOS {
            let slots = self.load_repo_advertisement_slots(true).await?;
            let decision = choose_repo_advertisement_slot(
                slots
                    .iter()
                    .map(|(subkey, value)| (*subkey, value.as_deref())),
                &repo_key,
            )?;

            let subkey = match decision {
                RepoAdvertisementSlot::AlreadyPresent(subkey) => {
                    info!(
                        "Own repo {} already advertised in group {} at subkey {}",
                        hex::encode(repo.id().opaque().ref_value()),
                        hex::encode(self.id().opaque().ref_value()),
                        subkey
                    );
                    return Ok(());
                }
                RepoAdvertisementSlot::Open(subkey) => subkey,
            };

            info!(
                "Advertising own repo {} to group {} at subkey {}",
                hex::encode(repo.id().opaque().ref_value()),
                hex::encode(self.id().opaque().ref_value()),
                subkey
            );

            if let Some(conflict) = self
                .routing_context
                .set_dht_value(
                    self.dht_record.key().clone(),
                    subkey,
                    repo_key.clone(),
                    Some(SetDHTValueOptions::default()),
                )
                .await?
            {
                if conflict.data() != repo_key.as_slice() {
                    warn!(
                        "Repo advertisement slot {} collided while setting; retrying",
                        subkey
                    );
                    continue;
                }
            }

            let stored_value = self
                .routing_context
                .get_dht_value(self.dht_record.key().clone(), subkey, true)
                .await?;

            match verify_repo_advertisement(
                stored_value.as_ref().map(|value| value.data()),
                &repo_key,
            ) {
                RepoAdvertisementVerification::Verified => {
                    info!(
                        "Successfully advertised own repo {} to group at subkey {}",
                        hex::encode(repo.id().opaque().ref_value()),
                        subkey
                    );
                    return Ok(());
                }
                RepoAdvertisementVerification::Missing => {
                    warn!(
                        "Repo advertisement slot {} was still empty; retrying",
                        subkey
                    );
                }
                RepoAdvertisementVerification::Collision => {
                    warn!(
                        "Repo advertisement slot {} was claimed by another repo; retrying",
                        subkey
                    );
                }
            }
        }

        Err(anyhow!(
            "Unable to advertise own repo without a repo-slot collision after {MAX_GROUP_REPOS} attempts"
        ))
    }

    pub async fn load_repo_from_network(
        &mut self,
        repo_id: RecordKey,
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
                    warn!("Failed to open DHT record: {e}. Retries left: {retries}");
                    if retries == 0 {
                        return Err(anyhow!(
                            "Unable to open DHT record, reached max retries: {e}"
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

    async fn load_repo_from_dht_value(&mut self, data: &[u8]) -> Result<RecordKey> {
        let repo_id = repo_record_key_from_dht_bytes(data)?;

        let cache_key = Self::repo_cache_key(&repo_id);
        if self.repos.lock().await.contains_key(&cache_key) {
            return Ok(repo_id);
        }
        self.load_repo_from_network(repo_id.clone()).await?;

        Ok(repo_id)
    }

    pub async fn load_repos_from_dht(&mut self) -> Result<()> {
        for (subkey, value) in self.load_repo_advertisement_slots(false).await? {
            let Some(repo_id_raw) = value else {
                continue;
            };

            match self.load_repo_from_dht_value(&repo_id_raw).await {
                Ok(_) => info!("Loaded repo from DHT subkey {subkey}"),
                Err(e) => warn!("Warning: Failed to load repo {subkey} from DHT: {e:?}"),
            }
        }

        Ok(())
    }

    pub async fn try_load_repo_from_disk(&mut self) -> bool {
        if let Err(err) = self.load_repo_from_disk().await {
            warn!("Unable to load own repo from disk: {err}");
            false
        } else {
            true
        }
    }

    pub async fn load_repo_from_disk(&mut self) -> Result<Repo> {
        let protected_store = self.veilid.protected_store().unwrap();

        let group_repo_key = format!("{}-repo", hex::encode(self.id().opaque().ref_value()));

        let key_bytes = protected_store
            .load_user_secret(group_repo_key)
            .map_err(|err| anyhow!("Unable to load repo from disk"))?
            .ok_or_else(|| anyhow!("No repo exists on disk for this group"))?;

        let repo_id = match String::from_utf8(key_bytes.clone())
            .ok()
            .and_then(|s| veilid_core::BareRecordKey::try_decode(&s).ok())
        {
            Some(bare_key) => RecordKey::new(CRYPTO_KIND_VLD0, bare_key),
            None => {
                // Legacy fallback: raw 32-byte opaque key without encryption key
                let mut id_bytes: [u8; 32] = [0; 32];
                id_bytes.copy_from_slice(&key_bytes);
                RecordKey::new(
                    CRYPTO_KIND_VLD0,
                    veilid_core::BareRecordKey::new(
                        veilid_core::BareOpaqueRecordKey::from(&id_bytes[..]),
                        None,
                    ),
                )
            }
        };

        let keypair = self.get_repo_keypair(repo_id.clone()).await?;

        let dht_record = self
            .routing_context
            .open_dht_record(
                repo_id.clone(),
                Some(KeyPair::new(
                    CRYPTO_KIND_VLD0,
                    veilid_core::BareKeyPair::new(
                        keypair.public_key.into_value(),
                        keypair.secret_key.clone().unwrap().into_value(),
                    ),
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
        let repo_dht_record = self
            .routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await?;

        // Identify the repo with the DHT record's key
        let repo_id = repo_dht_record.key().clone();

        // Use the group's encryption key for the repo
        let encryption_key = self.get_encryption_key().clone();

        let repo = Repo::new(
            repo_dht_record.clone(),
            encryption_key.clone(),
            // The repo is its own DHT record with its own keypair; its owner secret is
            // the write credential for that record.
            repo_dht_record.owner_secret().clone(),
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
            secret_key: repo_dht_record.owner_secret().clone(),
            encryption_key: encryption_key.clone(),
        };

        keypair
            .store_keypair(&protected_store)
            .await
            .map_err(|e| anyhow!(e))?;

        let group_repo_key = format!("{}-repo", hex::encode(self.id().opaque().ref_value()));
        // Store the full encoded record key (includes encryption key) so we can decrypt DHT values after restart.
        let key_bytes = repo.id().ref_value().encode().into_bytes();
        protected_store
            .save_user_secret(group_repo_key, &key_bytes)
            .map_err(|e| anyhow!("Unable to store repo id for group: {e}"))?;

        self.add_repo(repo).await?;

        self.advertise_own_repo().await?;

        // Ensure hash is published to DHT immediately for read-only members
        if let Some(owned_repo) = self.get_own_repo().await {
            // update_collection_on_dht will create the collection if it doesn't exist
            // and publish its hash to the DHT
            if let Err(e) = owned_repo.update_collection_on_dht().await {
                warn!("Failed to update hash on DHT immediately: {e}");
                // Don't fail repo creation, but log the warning
            }
        }

        self.get_own_repo()
            .await
            .ok_or_else(|| anyhow!("Unexpected error, created repo not persisted"))
    }

    async fn get_repo_keypair(&self, repo_id: RecordKey) -> Result<CommonKeypair> {
        let protected_store = self.veilid.protected_store()?;

        // Load keypair using the repo ID
        CommonKeypair::load_keypair(&protected_store, &repo_id)
            .await
            .map_err(|_| anyhow!("Failed to load keypair for repo_id: {repo_id:?}"))
    }

    fn repo_watch_subkeys() -> ValueSubkeyRangeSet {
        let (start, end) = repo_watch_subkey_bounds();
        ValueSubkeyRangeSet::single_range(start, end)
    }

    async fn register_repo_watch(
        routing_context: &RoutingContext,
        dht_record_key: &RecordKey,
        repo_subkeys: &ValueSubkeyRangeSet,
    ) -> Result<()> {
        let active = routing_context
            .watch_dht_values(
                dht_record_key.clone(),
                Some(repo_subkeys.clone()),
                None,
                None,
            )
            .await?;

        if active {
            info!("DHT watch active on group repo list {dht_record_key:?}");
            Ok(())
        } else {
            Err(anyhow!(
                "DHT watch registration returned inactive for group repo list {dht_record_key:?}"
            ))
        }
    }

    fn classify_repo_watch_update(
        value_change: &veilid_core::VeilidValueChange,
        dht_record_key: &RecordKey,
        repo_subkeys: &ValueSubkeyRangeSet,
    ) -> RepoWatchUpdate {
        if value_change.key != *dht_record_key {
            return RepoWatchUpdate::Ignore;
        }

        if value_change.count == 0 || value_change.subkeys.is_empty() {
            return RepoWatchUpdate::WatchEnded;
        }

        let changed_repo_subkeys = value_change.subkeys.intersect(repo_subkeys);
        if changed_repo_subkeys.is_empty() {
            RepoWatchUpdate::Ignore
        } else {
            RepoWatchUpdate::Changed
        }
    }

    pub async fn watch_changes<F, Fut>(&self, on_change: F) -> Result<()>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let routing_context = self.routing_context.clone();
        let dht_record_key = self.dht_record.key().clone();
        let repo_subkeys = Self::repo_watch_subkeys();
        let update_rx = self.update_rx.lock().await.resubscribe();
        Self::register_repo_watch(&routing_context, &dht_record_key, &repo_subkeys).await?;

        let register_watch = {
            let routing_context = routing_context.clone();
            let dht_record_key = dht_record_key.clone();
            let repo_subkeys = repo_subkeys.clone();
            move || {
                let routing_context = routing_context.clone();
                let dht_record_key = dht_record_key.clone();
                let repo_subkeys = repo_subkeys.clone();
                async move {
                    Self::register_repo_watch(&routing_context, &dht_record_key, &repo_subkeys)
                        .await
                }
            }
        };

        tokio::spawn(Self::watch_repo_update_loop(
            update_rx,
            dht_record_key,
            repo_subkeys,
            on_change,
            register_watch,
        ));

        Ok(())
    }

    async fn watch_repo_update_loop<F, Fut, R, RFut>(
        mut update_rx: broadcast::Receiver<VeilidUpdate>,
        dht_record_key: RecordKey,
        repo_subkeys: ValueSubkeyRangeSet,
        on_change: F,
        register_watch: R,
    ) where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
        R: Fn() -> RFut + Send + Sync + 'static,
        RFut: Future<Output = Result<()>> + Send + 'static,
    {
        loop {
            match update_rx.recv().await {
                Ok(VeilidUpdate::ValueChange(value_change)) => {
                    match Self::classify_repo_watch_update(
                        &value_change,
                        &dht_record_key,
                        &repo_subkeys,
                    ) {
                        RepoWatchUpdate::Ignore => continue,
                        RepoWatchUpdate::WatchEnded => {
                            warn!(
                                "DHT watch ended for group repo list {dht_record_key:?}; re-registering"
                            );
                            let mut retry_delay = Duration::from_secs(1);
                            loop {
                                match register_watch().await {
                                    Ok(()) => {
                                        if let Err(e) = on_change().await {
                                            error!(
                                                "Failed to reconcile group DHT after watch re-registration: {e:?}"
                                            );
                                        }
                                        break;
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to re-register DHT watch for group repo list {dht_record_key:?}: {e:?}"
                                        );
                                        tokio::time::sleep(retry_delay).await;
                                        retry_delay = std::cmp::min(
                                            retry_delay.saturating_mul(2),
                                            Duration::from_secs(60),
                                        );
                                    }
                                }
                            }
                        }
                        RepoWatchUpdate::Changed => {
                            if let Err(e) = on_change().await {
                                error!("Failed to handle group DHT change: {e:?}");
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    warn!("Missed {count} Veilid updates while watching group repo list");
                    if let Err(e) = on_change().await {
                        error!("Failed to handle lagged group DHT updates: {e:?}");
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("Veilid update channel closed while watching group repo list");
                    break;
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::sync::Notify;
    use tokio::time::{sleep, timeout};

    fn test_record_key(byte: u8) -> RecordKey {
        let bytes = [byte; 32];
        RecordKey::new(
            CRYPTO_KIND_VLD0,
            veilid_core::BareRecordKey::new(
                veilid_core::BareOpaqueRecordKey::from(&bytes[..]),
                None,
            ),
        )
    }

    fn encoded_record_key(byte: u8) -> String {
        test_record_key(byte).ref_value().encode()
    }

    #[test]
    fn repo_advertisement_slot_reuses_existing_slot_for_same_repo() {
        let repo_key = b"repo-a";
        let decision =
            choose_repo_advertisement_slot([(1, Some(repo_key.as_slice())), (2, None)], repo_key)
                .expect("slot should resolve");

        assert_eq!(decision, RepoAdvertisementSlot::AlreadyPresent(1));
    }

    #[test]
    fn repo_advertisement_slot_finds_existing_repo_after_hole() {
        let repo_key = b"repo-a";
        let other_repo = b"repo-b";
        let decision = choose_repo_advertisement_slot(
            [
                (1, Some(other_repo.as_slice())),
                (2, None),
                (3, Some(repo_key.as_slice())),
            ],
            repo_key,
        )
        .expect("slot should resolve");

        assert_eq!(decision, RepoAdvertisementSlot::AlreadyPresent(3));
    }

    #[test]
    fn concurrent_repo_slot_collision_retries_next_open_slot() {
        let repo_key = b"repo-a";
        let other_repo = b"repo-b";
        let first = choose_repo_advertisement_slot(
            [(1, None), (2, None), (3, Some(other_repo.as_slice()))],
            repo_key,
        )
        .expect("first open slot should resolve");
        assert_eq!(first, RepoAdvertisementSlot::Open(1));

        let verification =
            verify_repo_advertisement(Some(other_repo.as_slice()), repo_key.as_slice());
        assert_eq!(verification, RepoAdvertisementVerification::Collision);

        let retry = choose_repo_advertisement_slot(
            [
                (1, Some(other_repo.as_slice())),
                (2, None),
                (3, Some(other_repo.as_slice())),
            ],
            repo_key,
        )
        .expect("retry slot should resolve");
        assert_eq!(retry, RepoAdvertisementSlot::Open(2));
    }

    #[test]
    fn repo_slot_verification_detects_missing_value() {
        assert_eq!(
            verify_repo_advertisement(None, b"repo-a"),
            RepoAdvertisementVerification::Missing
        );
    }

    #[test]
    fn repo_watch_changes_scans_all_repo_slots_without_group_name_slot() {
        assert_eq!(repo_watch_subkey_bounds(), (1, MAX_GROUP_REPOS));
    }

    #[test]
    fn repo_record_key_from_dht_bytes_accepts_encoded_record_key() {
        let encoded = encoded_record_key(8);
        let decoded = repo_record_key_from_dht_bytes(encoded.as_bytes())
            .expect("encoded record key should parse");

        assert_eq!(decoded.ref_value().encode(), encoded);
    }

    #[test]
    fn repo_record_key_from_dht_bytes_accepts_legacy_opaque_key() {
        let legacy = [9u8; 32];
        let decoded = repo_record_key_from_dht_bytes(&legacy).expect("legacy key should parse");

        assert_eq!(decoded.opaque().ref_value().bytes().as_ref(), &legacy);
    }

    #[test]
    fn repo_record_key_from_dht_bytes_rejects_corrupted_value() {
        let err = repo_record_key_from_dht_bytes(&[0xff, 0xfe, 0xfd])
            .expect_err("invalid dht value should fail");
        assert!(err.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn repo_watch_subkeys_uses_bounded_repo_slots_without_group_name_slot() {
        let repo_subkeys = Group::repo_watch_subkeys();

        assert!(!repo_subkeys
            .intersect(&ValueSubkeyRangeSet::single(1))
            .is_empty());
        assert!(!repo_subkeys
            .intersect(&ValueSubkeyRangeSet::single(MAX_GROUP_REPOS))
            .is_empty());
        assert!(repo_subkeys
            .intersect(&ValueSubkeyRangeSet::single(0))
            .is_empty());
        assert!(repo_subkeys
            .intersect(&ValueSubkeyRangeSet::single(MAX_GROUP_REPOS + 1))
            .is_empty());
    }

    fn value_change(
        key: RecordKey,
        subkeys: ValueSubkeyRangeSet,
        count: u32,
    ) -> veilid_core::VeilidValueChange {
        veilid_core::VeilidValueChange {
            key,
            subkeys,
            count,
            value: None,
        }
    }

    #[test]
    fn repo_watch_update_classification_filters_value_changes() {
        let group_key = test_record_key(1);
        let other_key = test_record_key(2);
        let repo_subkeys = Group::repo_watch_subkeys();

        assert_eq!(
            Group::classify_repo_watch_update(
                &value_change(other_key, ValueSubkeyRangeSet::single(1), 1),
                &group_key,
                &repo_subkeys,
            ),
            RepoWatchUpdate::Ignore
        );
        assert_eq!(
            Group::classify_repo_watch_update(
                &value_change(group_key.clone(), ValueSubkeyRangeSet::single(0), 1),
                &group_key,
                &repo_subkeys,
            ),
            RepoWatchUpdate::Ignore
        );
        assert_eq!(
            Group::classify_repo_watch_update(
                &value_change(group_key.clone(), ValueSubkeyRangeSet::single(1), 1),
                &group_key,
                &repo_subkeys,
            ),
            RepoWatchUpdate::Changed
        );
        assert_eq!(
            Group::classify_repo_watch_update(
                &value_change(group_key.clone(), ValueSubkeyRangeSet::new(), 1),
                &group_key,
                &repo_subkeys,
            ),
            RepoWatchUpdate::WatchEnded
        );
        assert_eq!(
            Group::classify_repo_watch_update(
                &value_change(group_key.clone(), ValueSubkeyRangeSet::single(1), 0),
                &group_key,
                &repo_subkeys,
            ),
            RepoWatchUpdate::WatchEnded
        );
    }

    #[tokio::test]
    async fn repo_watch_update_loop_invokes_callback_for_matching_value_change() -> Result<()> {
        let (update_tx, update_rx) = broadcast::channel(8);
        let group_key = test_record_key(1);
        let other_key = test_record_key(2);
        let repo_subkeys = Group::repo_watch_subkeys();
        let change_count = Arc::new(AtomicUsize::new(0));
        let change_notify = Arc::new(Notify::new());
        let callback_count = Arc::clone(&change_count);
        let callback_notify = Arc::clone(&change_notify);

        let update_loop = tokio::spawn(Group::watch_repo_update_loop(
            update_rx,
            group_key.clone(),
            repo_subkeys,
            move || {
                let callback_count = Arc::clone(&callback_count);
                let callback_notify = Arc::clone(&callback_notify);
                async move {
                    callback_count.fetch_add(1, Ordering::SeqCst);
                    callback_notify.notify_waiters();
                    Ok(())
                }
            },
            || async { Ok(()) },
        ));

        update_tx.send(VeilidUpdate::ValueChange(Box::new(value_change(
            group_key.clone(),
            ValueSubkeyRangeSet::single(1),
            1,
        ))))?;

        timeout(Duration::from_secs(1), async {
            loop {
                if change_count.load(Ordering::SeqCst) > 0 {
                    break;
                }
                change_notify.notified().await;
            }
        })
        .await
        .map_err(|_| anyhow!("Timed out waiting for watch callback"))?;

        update_tx.send(VeilidUpdate::ValueChange(Box::new(value_change(
            group_key,
            ValueSubkeyRangeSet::single(0),
            1,
        ))))?;
        update_tx.send(VeilidUpdate::ValueChange(Box::new(value_change(
            other_key,
            ValueSubkeyRangeSet::single(1),
            1,
        ))))?;
        sleep(Duration::from_millis(50)).await;

        assert_eq!(
            change_count.load(Ordering::SeqCst),
            1,
            "only matching group repo subkey updates should invoke the callback"
        );

        drop(update_tx);
        timeout(Duration::from_secs(1), update_loop).await??;

        Ok(())
    }

    #[tokio::test]
    async fn repo_watch_update_loop_re_registers_and_reconciles_when_watch_ends() -> Result<()> {
        let (update_tx, update_rx) = broadcast::channel(8);
        let group_key = test_record_key(1);
        let repo_subkeys = Group::repo_watch_subkeys();
        let change_count = Arc::new(AtomicUsize::new(0));
        let register_count = Arc::new(AtomicUsize::new(0));
        let change_notify = Arc::new(Notify::new());
        let callback_count = Arc::clone(&change_count);
        let callback_notify = Arc::clone(&change_notify);
        let callback_register_count = Arc::clone(&register_count);

        let update_loop = tokio::spawn(Group::watch_repo_update_loop(
            update_rx,
            group_key.clone(),
            repo_subkeys,
            move || {
                let callback_count = Arc::clone(&callback_count);
                let callback_notify = Arc::clone(&callback_notify);
                async move {
                    callback_count.fetch_add(1, Ordering::SeqCst);
                    callback_notify.notify_waiters();
                    Ok(())
                }
            },
            move || {
                let callback_register_count = Arc::clone(&callback_register_count);
                async move {
                    callback_register_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));

        update_tx.send(VeilidUpdate::ValueChange(Box::new(value_change(
            group_key,
            ValueSubkeyRangeSet::new(),
            1,
        ))))?;

        timeout(Duration::from_secs(1), async {
            loop {
                if change_count.load(Ordering::SeqCst) > 0 {
                    break;
                }
                change_notify.notified().await;
            }
        })
        .await
        .map_err(|_| anyhow!("Timed out waiting for watch reconciliation"))?;

        assert_eq!(
            register_count.load(Ordering::SeqCst),
            1,
            "watch-ended updates should re-register the DHT watch"
        );
        assert_eq!(
            change_count.load(Ordering::SeqCst),
            1,
            "watch-ended updates should reconcile once after re-registration"
        );

        drop(update_tx);
        timeout(Duration::from_secs(1), update_loop).await??;

        Ok(())
    }
}
