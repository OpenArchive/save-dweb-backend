use crate::common::{init_veilid, make_route, CommonKeypair, DHTEntity};
use crate::constants::KNOWN_GROUP_LIST;
use crate::group::{Group, URL_DHT_KEY, URL_ENCRYPTION_KEY, URL_PUBLIC_KEY, URL_SECRET_KEY};
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use iroh::node::Node;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use url::Url;
use veilid_core::{
    PublicKey, SecretKey, RecordKey, BareRecordKey, CryptoSystem,
    DHTSchema, KeyPair, ProtectedStore, RoutingContext, SharedSecret,
    UpdateCallback, VeilidAPI, VeilidAPIError, VeilidConfig, VeilidConfigProtectedStore, VeilidUpdate,
    CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use veilid_iroh_blobs::tunnels::{OnNewRouteCallback, OnRouteDisconnectedCallback};

#[derive(Serialize, Deserialize, Debug)]
pub struct KnownGroupList {
    groups: Vec<RecordKey>,
}

pub struct BackendInner {
    path: PathBuf,
    veilid_api: Option<VeilidAPI>,
    update_rx: Option<broadcast::Receiver<VeilidUpdate>>,
    groups: HashMap<String, Box<Group>>,  // Key is hex-encoded opaque value for stable lookups
    pub iroh_blobs: Option<VeilidIrohBlobs>,
    on_new_route_callback: Option<OnNewRouteCallback>,
    initialized: bool,
}

/// Convert RecordKey to stable cache key (hex-encoded opaque bytes)
fn group_cache_key(record_key: &RecordKey) -> String {
    hex::encode(record_key.opaque().ref_value())
}

impl BackendInner {
    async fn save_known_group_ids(&self) -> Result<()> {
        // Collect the actual RecordKeys from the groups (using group.id())
        let groups: Vec<RecordKey> = self.groups.values().map(|g| g.id()).collect();

        let info = KnownGroupList { groups };

        info!("Saving group IDs {info:?}");
        let data =
            serde_cbor::to_vec(&info).map_err(|e| anyhow!("Failed to serialize keypair: {e}"))?;
        self.veilid()?
            .protected_store()?
            .save_user_secret(KNOWN_GROUP_LIST, &data)
            .map_err(|e: VeilidAPIError| anyhow!("Unable to store known group IDs: {e}"))?;
        Ok(())
    }

    fn veilid(&self) -> Result<VeilidAPI> {
        Ok(self
            .veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API not initialized"))?
            .clone())
    }

    fn iroh_blobs(&self) -> Result<VeilidIrohBlobs> {
        if !self.initialized {
            return Err(anyhow!("Veilid Iroh Blobs API not initialized. Call start() first and wait for initialization to complete."));
        }
        Ok(self
            .iroh_blobs
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid Iroh Blobs API not initialized"))?
            .clone())
    }

    fn is_initialized(&self) -> bool {
        self.initialized && self.iroh_blobs.is_some() && self.veilid_api.is_some()
    }
}

#[derive(Clone)]
pub struct Backend {
    inner: Arc<Mutex<BackendInner>>,
}

impl Backend {
    pub fn new(base_path: &Path) -> Result<Self> {
        let inner = BackendInner {
            path: base_path.to_path_buf(),
            veilid_api: None,
            update_rx: None,
            groups: HashMap::new(),
            iroh_blobs: None,
            on_new_route_callback: None,
            initialized: false,
        };

        let backend = Backend {
            inner: Arc::new(Mutex::new(inner)),
        };

        Ok(backend)
    }

    pub async fn from_dependencies(
        base_path: &Path,
        veilid_api: VeilidAPI,
        update_rx: broadcast::Receiver<VeilidUpdate>,
        store: iroh_blobs::store::fs::Store,
    ) -> Result<Self> {
        let inner = BackendInner {
            path: base_path.to_path_buf(),
            veilid_api: Some(veilid_api.clone()),
            update_rx: Some(update_rx),
            groups: HashMap::new(),
            iroh_blobs: None,
            on_new_route_callback: None,
            initialized: false,
        };

        let backend = Backend {
            inner: Arc::new(Mutex::new(inner)),
        };

        let inner_clone = backend.inner.clone();

        let on_new_route_callback: OnNewRouteCallback = Arc::new(move |route_id, route_id_blob| {
            let inner = inner_clone.clone();
            info!("Re-generating route");
            tokio::spawn(async move {
                let inner = inner.lock().await;

                if let Some(on_new_route) = &inner.on_new_route_callback {
                    on_new_route(route_id, route_id_blob)
                }

                for group in inner.groups.clone().into_values() {
                    if let Some(repo) = group.get_own_repo().await {
                        if let Err(err) = repo.update_route_on_dht().await {
                            let group_id = group.id();
                            let repo_id = repo.id();
                            error!("Unable to update route after rebuild in group {group_id:?} in repo {repo_id:?}: {err}");
                        }
                    }
                }
            });
        });

        let on_disconnected_callback: OnRouteDisconnectedCallback = Arc::new(move || {
            warn!("Route died");
        });

        let (route_id, route_id_blob) = make_route(&veilid_api).await?;
        let routing_context = veilid_api.routing_context()?;

        let mut inner = backend.inner.lock().await;

        // Initialize iroh_blobs
        let config = veilid_iroh_blobs::iroh::VeilidIrohBlobsConfig {
            veilid: veilid_api.clone(),
            router: routing_context,
            route_id_blob,
            route_id,
            updates: inner.update_rx.as_ref().unwrap().resubscribe(),
            store,
            on_route_disconnected_callback: Some(on_disconnected_callback), // TODO: Notify application of route closure?
            on_new_route_callback: Some(on_new_route_callback),
        };
        inner.iroh_blobs = Some(VeilidIrohBlobs::new(config));
        inner.initialized = true;
        info!("Veilid Iroh Blobs initialized via from_dependencies");

        drop(inner);

        Ok(backend)
    }

    pub async fn start(&self) -> Result<()> {
        self.start_with_namespace(None).await
    }

    pub async fn start_with_namespace(&self, namespace: Option<String>) -> Result<()> {
        let mut inner = self.inner.lock().await;

        if inner.veilid_api.is_some() {
            #[cfg(test)]
            {
                // In tests, allow stop-then-restart when already initialized (process may not fully restart).
                drop(inner);
                self.stop().await?;
                inner = self.inner.lock().await;
                info!("Re-initializing Veilid for testing purposes.");
            }
            #[cfg(not(test))]
            {
                drop(inner);
                return Err(anyhow!("Veilid already initialized. Call stop() first, then start()."));
            }
        }
        info!("Starting on {}", inner.path.display());

        let base_dir = inner.path.clone();
        fs::create_dir_all(&base_dir).await?;

        let namespace_str = namespace.unwrap_or_else(|| "openarchive".to_string());
        let (veilid_api, mut update_rx) = init_veilid(&base_dir, namespace_str).await?;

        inner.veilid_api = Some(veilid_api.clone());
        inner.update_rx = Some(update_rx.resubscribe());

        // Initialize iroh_blobs store
        let store = iroh_blobs::store::fs::Store::load(base_dir.join("iroh")).await?;

        // Create route_id and route_id_blob
        let (route_id, route_id_blob) = make_route(&veilid_api).await?;

        // Get veilid_api and routing_context
        let routing_context = veilid_api.routing_context()?;

        let inner_clone = self.inner.clone();

        let on_new_route_callback: OnNewRouteCallback = Arc::new(move |route_id, route_id_blob| {
            let inner = inner_clone.clone();
            info!("Re-generating route");
            tokio::spawn(async move {
                let inner = inner.lock().await;

                if let Some(on_new_route) = &inner.on_new_route_callback {
                    on_new_route(route_id, route_id_blob)
                }

                for group in inner.groups.clone().into_values() {
                    if let Some(repo) = group.get_own_repo().await {
                        if let Err(err) = repo.update_route_on_dht().await {
                            let group_id = group.id();
                            let repo_id = repo.id();
                            error!("Unable to update route after rebuild in group {group_id:?} in repo {repo_id:?}: {err}");
                        }
                    }
                }
            });
        });

        // Initialize iroh_blobs
        let config = veilid_iroh_blobs::iroh::VeilidIrohBlobsConfig {
            veilid: veilid_api.clone(),
            router: routing_context,
            route_id_blob,
            route_id,
            updates: update_rx.resubscribe(),
            store,
            on_route_disconnected_callback: None, // TODO: Notify application of route closure?
            on_new_route_callback: Some(on_new_route_callback),
        };
        inner.iroh_blobs = Some(VeilidIrohBlobs::new(config));
        inner.initialized = true;
        info!("Veilid Iroh Blobs initialized via start()");

        drop(inner);

        if let Err(e) = self.load_known_groups().await {
            warn!("No known groups on start: {e}");
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        info!("Stopping Backend...");
        if let Some(iroh_blobs) = inner.iroh_blobs.take() {
            info!("Shutting down Veilid Iroh Blobs");
            iroh_blobs.shutdown().await?;
            info!("Veilid Iroh Blobs shut down successfully");
        }
        if inner.veilid_api.is_some() {
            info!("Shutting down Veilid API");
            let veilid = inner.veilid_api.take();
            veilid.unwrap().shutdown().await;
            info!("Veilid API shut down successfully");
            inner.groups = HashMap::new();
        }
        inner.initialized = false;
        Ok(())
    }

    pub async fn set_on_new_route_callback(
        &self,
        on_new_route_connected_callback: OnNewRouteCallback,
    ) {
        let mut inner = self.inner.lock().await;
        inner.on_new_route_callback = Some(on_new_route_connected_callback);
    }

    pub async fn join_from_url(&self, url_string: &str) -> Result<Box<Group>> {
        let keys = parse_url(url_string)?;
        self.join_group(keys).await
    }

    pub async fn get_route_id_blob(&self) -> Result<Vec<u8>> {
        if let Some(blobs) = self.get_iroh_blobs().await {
            Ok(blobs.route_id_blob().await)
        } else {
            Err(anyhow!("Veilid not initialized"))
        }
    }

    pub async fn join_group(&self, keys: CommonKeypair) -> Result<Box<Group>> {
        let mut inner = self.inner.lock().await;

        // Check initialization state before proceeding
        if !inner.is_initialized() {
            return Err(anyhow!(
                "Backend not initialized. Ensure start() has been called and completed successfully before joining groups."
            ));
        }
        
        // Check if group is already cached with a writable repo
        let cache_key = group_cache_key(&keys.id);
        if let Some(cached_group) = inner.groups.get(&cache_key) {
            if cached_group.get_own_repo().await.is_some() {
                info!("Group already cached with writable repo, returning cached group");
                return Ok(cached_group.clone());
            }
        }
        
        info!("Joining group - backend is initialized");
        let iroh_blobs = inner.iroh_blobs()?;
        let veilid = inner.veilid()?;

        let routing_context = veilid.routing_context()?;
        let crypto_system = veilid
            .crypto()?
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"));

        let record_key = keys.id;
        // In v0.5.1, DHT encryption is enabled by default, so we need to provide the owner keypair
        // to decrypt. We get this from the URL that was shared with us.
        let bare_keypair = veilid_core::BareKeyPair::new(
            keys.public_key.clone().into_value(),
            keys.secret_key.clone().unwrap().into_value(),
        );
        let dht_record = routing_context
            .open_dht_record(
                record_key.clone(),
                Some(KeyPair::new(CRYPTO_KIND_VLD0, bare_keypair)),
            )
            .await?;

        let mut group = Group::new(
            dht_record.clone(),
            keys.encryption_key.clone(),
            routing_context,
            veilid.clone(),
            iroh_blobs.clone(),
        );

        // Try to load existing repo from disk
        group.try_load_repo_from_disk().await;
        
        // Load repos from other peers in the group
        group.load_repos_from_dht().await?;
        
        // If we don't have our own repo, create one automatically
        // This allows the device to participate in the group and upload files
        // Check for a writable repo after BOTH disk and DHT loading complete
        if group.get_own_repo().await.is_none() {
            info!("No own repo found when joining group, creating one automatically");
            if let Err(e) = group.create_repo().await {
                warn!("Failed to auto-create repo when joining group: {e}");
                // Continue anyway - user can create repo manually later
            } else {
                info!("Successfully auto-created repo when joining group");
            }
        }

        inner.groups.insert(group_cache_key(&group.id()), Box::new(group.clone()));

        inner.save_known_group_ids().await?;

        Ok(Box::new(group))
    }

    pub async fn create_group(&self) -> Result<Group> {
        let mut inner = self.inner.lock().await;
        
        // Check initialization state before proceeding
        if !inner.is_initialized() {
            return Err(anyhow!(
                "Backend not initialized. Ensure start() has been called and completed successfully before creating groups."
            ));
        }
        
        info!("Creating group - backend is initialized");
        let iroh_blobs = inner.iroh_blobs()?;
        let veilid = inner.veilid()?;

        let routing_context = veilid.routing_context()?;
        let crypto = veilid.crypto()?;
        let crypto_system = crypto
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

        let schema = DHTSchema::dflt(65)?; // 64 members + a title
        let owner_keypair = crypto_system.generate_keypair();

        let dht_record = routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, Some(owner_keypair))
            .await?;

        let encryption_key = crypto_system.random_shared_secret();

        let group = Group::new(
            dht_record.clone(),
            encryption_key,
            routing_context,
            veilid.clone(),
            iroh_blobs.clone(),
        );

        let protected_store = veilid.protected_store().unwrap();
        CommonKeypair {
            id: group.id(),
            public_key: dht_record.owner().clone(),
            secret_key: group.get_secret_key(),
            encryption_key: group.get_encryption_key(),
        }
        .store_keypair(&protected_store)
        .await
        .map_err(|e| anyhow!(e))?;

        inner.groups.insert(group_cache_key(&group.id()), Box::new(group.clone()));

        inner.save_known_group_ids().await?;

        Ok(group)
    }

    pub async fn get_group(&self, record_key: &RecordKey) -> Result<Box<Group>> {
        let cache_key = group_cache_key(record_key);
        let cached_group = {
            let inner = self.inner.lock().await;
            inner.groups.get(&cache_key).cloned()
        };

        if let Some(group) = cached_group {
            return Ok(group);
        }

        let mut inner = self.inner.lock().await;
        
        // Check initialization state before proceeding
        if !inner.is_initialized() {
            return Err(anyhow!(
                "Backend not initialized. Ensure start() has been called and completed successfully."
            ));
        }
        
        let iroh_blobs = inner.iroh_blobs()?;
        let veilid = inner.veilid()?;

        let routing_context = veilid.routing_context()?;
        let protected_store = veilid.protected_store().unwrap();

        // Load the keypair associated with the record_key from the protected store
        let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, record_key)
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?;

        let crypto = veilid.crypto()?;
        let crypto_system = crypto
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

        // Use the owner key from the DHT record as the default writer
        let owner_key = retrieved_keypair.public_key; // Call the owner() method to get the owner key
        let owner_secret = retrieved_keypair.secret_key;
        let record_key = record_key.clone();

        let owner = owner_secret.map(|secret| {
            let bare_keypair = veilid_core::BareKeyPair::new(
                owner_key.into_value(),
                secret.into_value(),
            );
            KeyPair::new(CRYPTO_KIND_VLD0, bare_keypair)
        });

        // Reopen the DHT record with the owner key as the writer
        let dht_record = routing_context
            .open_dht_record(record_key.clone(), owner)
            .await?;

        let mut group = Group::new(
            dht_record.clone(),
            retrieved_keypair.encryption_key.clone(),
            routing_context,
            veilid.clone(),
            iroh_blobs.clone(),
        );

        group.try_load_repo_from_disk().await;
        group.load_repos_from_dht().await?;

        inner.groups.insert(group_cache_key(&group.id()), Box::new(group.clone()));

        drop(inner);

        Ok(Box::new(group))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        let mut inner = self.inner.lock().await;
        Ok(inner.groups.values().cloned().collect())
    }

    pub async fn load_known_groups(&self) -> Result<()> {
        for id in self.list_known_group_ids().await?.iter() {
            self.get_group(id).await?;
        }
        Ok(())
    }

    pub async fn list_known_group_ids(&self) -> Result<Vec<RecordKey>> {
        let mut inner = self.inner.lock().await;
        let veilid = inner.veilid()?;
        let data = veilid
            .protected_store()?
            .load_user_secret(KNOWN_GROUP_LIST)
            .map_err(|e: VeilidAPIError| anyhow!("Failed to load known groups: {e}"))?
            .ok_or_else(|| anyhow!("Known group list not found"))?;
        match serde_cbor::from_slice::<KnownGroupList>(&data) {
            Ok(info) => Ok(info.groups),
            Err(e) => {
                warn!(
                    "Failed to deserialize known group list (old format?): {e}; treating as empty"
                );
                Ok(Vec::new())
            }
        }
    }

    pub async fn close_group(&self, key: RecordKey) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let cache_key = group_cache_key(&key);
        if let Some(group) = inner.groups.remove(&cache_key) {
            group.close().await.map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!("Group not found"));
        }
        Ok(())
    }

    /// Invalidate cached group, forcing reload from DHT on next access
    pub async fn invalidate_group_cache(&self, record_key: &RecordKey) {
        let mut inner = self.inner.lock().await;
        inner.groups.remove(&group_cache_key(record_key));
        info!("Invalidated cache for group {}", hex::encode(record_key.opaque().ref_value()));
    }

    /// Force refresh a group's repos from DHT
    pub async fn refresh_group(&self, record_key: &RecordKey) -> Result<Box<Group>> {
        // Remove from cache
        self.invalidate_group_cache(record_key).await;
        // Fetch fresh from DHT
        self.get_group(record_key).await
    }

    pub async fn create_collection(&self) -> Result<Hash> {
        // Initialize a new Iroh Node in memory
        let node = Node::memory().spawn().await?;

        // Get the Client from the node
        let iroh_client = node.client().blobs();

        // Create an empty Collection
        let mut collection = Collection::default();

        // Tag options for creating the collection
        let tag_option = SetTagOption::Auto;

        // No tags to delete, so we pass an empty vector
        let tags_to_delete = Vec::new();

        // Use the iroh_client instance to create the collection and get the root hash
        let (root_hash, _tag) = iroh_client
            .create_collection(collection, tag_option, tags_to_delete)
            .await?;

        // Return the root hash
        Ok(root_hash)
    }

    pub async fn subscribe_updates(&self) -> Option<broadcast::Receiver<VeilidUpdate>> {
        let mut inner = self.inner.lock().await;
        inner.update_rx.as_ref().map(|rx| rx.resubscribe())
    }

    pub async fn get_veilid_api(&self) -> Option<VeilidAPI> {
        let mut inner = self.inner.lock().await;

        inner.veilid_api.clone()
    }

    pub async fn get_iroh_blobs(&self) -> Option<VeilidIrohBlobs> {
        let mut inner = self.inner.lock().await;
        inner.iroh_blobs.clone()
    }

    pub async fn get_routing_context(&self) -> Option<RoutingContext> {
        let veilid_api = self.get_veilid_api().await?;
        veilid_api.routing_context().ok()
    }

    /// Check if the backend is fully initialized and ready to use
    pub async fn is_initialized(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.is_initialized()
    }
}

fn find_query(url: &Url, key: &str) -> Result<String> {
    for (query_key, value) in url.query_pairs() {
        if query_key == key {
            return Ok(value.into_owned());
        }
    }

    Err(anyhow!("Unable to find parameter {key} in URL {url:?}"))
}

/// Decode a record key from a URL query parameter.
/// Expects the value produced by `RecordKey::ref_value().encode()` (e.g. from `Group::get_url()`).
/// Round-trip is covered by the `test_join` test.
pub fn record_key_from_query(url: &Url, key: &str) -> Result<RecordKey> {
    let value = find_query(url, key)?;
    let bare = BareRecordKey::try_decode(&value)?;
    Ok(RecordKey::new(CRYPTO_KIND_VLD0, bare))
}

pub fn public_key_from_query(url: &Url, key: &str) -> Result<PublicKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(PublicKey::new(CRYPTO_KIND_VLD0, veilid_core::BarePublicKey::from(&key_vec[..])))
}

pub fn secret_key_from_query(url: &Url, key: &str) -> Result<SecretKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(SecretKey::new(CRYPTO_KIND_VLD0, veilid_core::BareSecretKey::from(&key_vec[..])))
}

pub fn shared_secret_from_query(url: &Url, key: &str) -> Result<SharedSecret> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(SharedSecret::new(CRYPTO_KIND_VLD0, veilid_core::BareSharedSecret::from(&key_vec[..])))
}

pub fn parse_url(url_string: &str) -> Result<CommonKeypair> {
    let url = Url::parse(url_string)?;

    let id = record_key_from_query(&url, URL_DHT_KEY)?;
    let encryption_key = shared_secret_from_query(&url, URL_ENCRYPTION_KEY)?;
    let public_key = public_key_from_query(&url, URL_PUBLIC_KEY)?;
    let secret_key = Some(secret_key_from_query(&url, URL_SECRET_KEY)?);

    Ok(CommonKeypair {
        id,
        public_key,
        secret_key,
        encryption_key,
    })
}
