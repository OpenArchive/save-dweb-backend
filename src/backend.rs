use crate::backend;
use crate::common::{init_veilid, make_route, CommonKeypair, DHTEntity};
use crate::constants::KNOWN_GROUP_LIST;
use crate::group::{self, Group, URL_DHT_KEY, URL_ENCRYPTION_KEY, URL_PUBLIC_KEY, URL_SECRET_KEY};
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::builder::Str;
use hex::ToHex;
use iroh::node::Node;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::sync::{
    broadcast,
    mpsc::{self, Receiver},
    oneshot,
};
use tracing::info;
use url::Url;
use veilid_core::{
    api_startup_config, PublicKey, SecretKey, RecordKey, CryptoSystem,
    CryptoTyped, DHTSchema, KeyPair, ProtectedStore, RoutingContext, SharedSecret, TypedRecordKey,
    UpdateCallback, VeilidAPI, VeilidConfig, VeilidConfigProtectedStore, VeilidUpdate,
    CRYPTO_KEY_LENGTH, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use veilid_iroh_blobs::tunnels::{OnNewRouteCallback, OnRouteDisconnectedCallback};
use xdg::BaseDirectories;

#[derive(Serialize, Deserialize, Debug)]
pub struct KnownGroupList {
    groups: Vec<RecordKey>,
}

pub struct BackendInner {
    path: PathBuf,
    veilid_api: Option<VeilidAPI>,
    update_rx: Option<broadcast::Receiver<VeilidUpdate>>,
    groups: HashMap<RecordKey, Box<Group>>,
    pub iroh_blobs: Option<VeilidIrohBlobs>,
    on_new_route_callback: Option<OnNewRouteCallback>,
    initialized: bool,
}

impl BackendInner {
    async fn save_known_group_ids(&self) -> Result<()> {
        let groups = self.groups.clone().into_keys().collect();

        let info = KnownGroupList { groups };

        println!("Saving group IDs {info:?}");
        let data =
            serde_cbor::to_vec(&info).map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;
        self.veilid()?
            .protected_store()?
            .save_user_secret(KNOWN_GROUP_LIST, &data)
            .map_err(|e| anyhow!("Unable to store known group IDs: {}", e))?;
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
            println!("Re-generating route");
            tokio::spawn(async move {
                let inner = inner.lock().await;

                if let Some(on_new_route) = &inner.on_new_route_callback {
                    on_new_route(route_id, route_id_blob)
                }

                for group in inner.groups.clone().into_values() {
                    if let Some(repo) = group.get_own_repo().await {
                        if let Err(err) = repo.update_route_on_dht().await {
                            eprintln!(
                                "Unable to update route after rebuild in group {} in repo {}: {}",
                                group.id(),
                                repo.id(),
                                err
                            );
                        }
                    }
                }
            });
        });

        let on_disconnected_callback: OnRouteDisconnectedCallback = Arc::new(move || {
            println!("Route died");
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
        let mut inner = self.inner.lock().await;

        if inner.veilid_api.is_some() {
            return Err(anyhow!("Veilid already initialized"));
        }
        println!("Starting on {}", inner.path.display());

        let base_dir = inner.path.clone();
        fs::create_dir_all(&base_dir).await?;

        let (veilid_api, mut update_rx) = init_veilid(&base_dir, "openarchive".to_string()).await?;

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
            println!("Re-generating route");
            tokio::spawn(async move {
                let inner = inner.lock().await;

                if let Some(on_new_route) = &inner.on_new_route_callback {
                    on_new_route(route_id, route_id_blob)
                }

                for group in inner.groups.clone().into_values() {
                    if let Some(repo) = group.get_own_repo().await {
                        if let Err(err) = repo.update_route_on_dht().await {
                            eprintln!(
                                "Unable to update route after rebuild in group {} in repo {}: {}",
                                group.id(),
                                repo.id(),
                                err
                            );
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

        if let Err(err) = self.load_known_groups().await {
            eprintln!("No known groups on start");
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        println!("Stopping Backend...");
        if let Some(iroh_blobs) = inner.iroh_blobs.take() {
            println!("Shutting down Veilid Iroh Blobs");
            iroh_blobs.shutdown().await?;
            println!("Veilid Iroh Blobs shut down successfully");
        }
        if inner.veilid_api.is_some() {
            println!("Shutting down Veilid API");
            let veilid = inner.veilid_api.take();
            veilid.unwrap().shutdown().await;
            println!("Veilid API shut down successfully");
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
        
        info!("Joining group - backend is initialized");
        let iroh_blobs = inner.iroh_blobs()?;
        let veilid = inner.veilid()?;

        let routing_context = veilid.routing_context()?;
        let crypto_system = veilid
            .crypto()?
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"));

        let record_key = TypedRecordKey::new(CRYPTO_KIND_VLD0, keys.id);
        // First open the DHT record
        let dht_record = routing_context
            .open_dht_record(record_key.clone(), None) // Don't pass a writer here yet
            .await?;

        // Use the owner key from the DHT record as the default writer
        let owner_key = dht_record.owner(); // Call the owner() method to get the owner key

        // Reopen the DHT record with the owner key as the writer
        let dht_record = routing_context
            .open_dht_record(
                record_key.clone(),
                Some(KeyPair::new(
                    owner_key.clone(),
                    keys.secret_key.clone().unwrap(),
                )),
            )
            .await?;

        let mut group = Group::new(
            dht_record.clone(),
            keys.encryption_key.clone(),
            routing_context,
            veilid.clone(),
            iroh_blobs.clone(),
        );

        group.try_load_repo_from_disk().await;
        group.load_repos_from_dht().await?;

        inner.groups.insert(group.id(), Box::new(group.clone()));

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
        let kind = Some(CRYPTO_KIND_VLD0);
        let owner_keypair = crypto_system.generate_keypair();

        let dht_record = routing_context
            .create_dht_record(schema, Some(owner_keypair), kind)
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

        inner.groups.insert(group.id(), Box::new(group.clone()));

        inner.save_known_group_ids().await?;

        Ok(group)
    }

    pub async fn get_group(&self, record_key: &RecordKey) -> Result<Box<Group>> {
        let mut inner = self.inner.lock().await;
        if let Some(group) = inner.groups.get(record_key) {
            return Ok(group.clone());
        }
        
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
        let record_key = TypedRecordKey::new(CRYPTO_KIND_VLD0, *record_key);

        let owner = owner_secret.map(|secret| KeyPair::new(owner_key, secret));

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

        inner.groups.insert(group.id(), Box::new(group.clone()));

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
            .map_err(|_| anyhow!("Failed to load keypair"))?
            .ok_or_else(|| anyhow!("Keypair not found"))?;
        let info: KnownGroupList =
            serde_cbor::from_slice(&data).map_err(|_| anyhow!("Failed to deserialize keypair"))?;
        Ok(info.groups)
    }

    pub async fn close_group(&self, key: RecordKey) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if let Some(group) = inner.groups.remove(&key) {
            group.close().await.map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!("Group not found"));
        }
        Ok(())
    }

    /// Invalidate cached group, forcing reload from DHT on next access
    pub async fn invalidate_group_cache(&self, record_key: &RecordKey) {
        let mut inner = self.inner.lock().await;
        inner.groups.remove(record_key);
        info!("Invalidated cache for group {}", record_key.encode_hex::<String>());
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

async fn wait_for_network(update_rx: &mut broadcast::Receiver<VeilidUpdate>) -> Result<()> {
    while let Ok(update) = update_rx.recv().await {
        if let VeilidUpdate::Attachment(attachment_state) = update {
            if attachment_state.public_internet_ready {
                println!("Public internet ready!");
                break;
            }
        }
    }
    Ok(())
}

fn find_query(url: &Url, key: &str) -> Result<String> {
    for (query_key, value) in url.query_pairs() {
        if query_key == key {
            return Ok(value.into_owned());
        }
    }

    Err(anyhow!("Unable to find parameter {} in URL {:?}", key, url))
}

pub fn record_key_from_query(url: &Url, key: &str) -> Result<RecordKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(RecordKey::new(key_vec))
}

pub fn public_key_from_query(url: &Url, key: &str) -> Result<PublicKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(PublicKey::new(key_vec))
}

pub fn secret_key_from_query(url: &Url, key: &str) -> Result<SecretKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(SecretKey::new(key_vec))
}

pub fn shared_secret_from_query(url: &Url, key: &str) -> Result<SharedSecret> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; 32] = [0; 32];
    key_vec.copy_from_slice(bytes.as_slice());
    Ok(SharedSecret::new(key_vec))
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
