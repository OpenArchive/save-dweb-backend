use crate::common::{init_veilid, make_route, CommonKeypair, DHTEntity};
use crate::constants::KNOWN_GROUP_LIST;
use crate::group::{self, Group, URL_DHT_KEY, URL_ENCRYPTION_KEY, URL_PUBLIC_KEY, URL_SECRET_KEY};
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::builder::Str;
use iroh::node::Node;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem;
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
    api_startup_config, vld0_generate_keypair, CryptoKey, CryptoSystem, CryptoSystemVLD0,
    CryptoTyped, DHTSchema, KeyPair, ProtectedStore, RoutingContext, SharedSecret, TypedKey,
    UpdateCallback, VeilidAPI, VeilidConfigInner, VeilidConfigProtectedStore, VeilidUpdate,
    CRYPTO_KEY_LENGTH, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use veilid_iroh_blobs::tunnels::OnNewRouteCallback;
use xdg::BaseDirectories;

#[derive(Serialize, Deserialize)]
pub struct KnownGroupList {
    groups: Vec<CryptoKey>,
}

pub struct BackendInner {
    path: PathBuf,
    veilid_api: Option<VeilidAPI>,
    update_rx: Option<broadcast::Receiver<VeilidUpdate>>,
    groups: HashMap<CryptoKey, Box<Group>>,
    repos: HashMap<CryptoKey, Box<Repo>>,
    pub iroh_blobs: Option<VeilidIrohBlobs>,
}

impl BackendInner {
    async fn save_known_group_ids(&self) -> Result<()> {
        let groups = self.groups.clone().into_keys().collect();

        let info = KnownGroupList { groups };

        let data =
            serde_cbor::to_vec(&info).map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;
        self.get_protected_store()?
            .save_user_secret(KNOWN_GROUP_LIST, &data)
            .await
            .map_err(|e| anyhow!("Unable to store keypair: {}", e))?;
        Ok(())
    }

    fn veilid(&self) -> Result<VeilidAPI> {
        self.veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API not initialized"))
            .map(|store| store.clone())
    }

    fn get_protected_store(&self) -> Result<ProtectedStore> {
        let veilid_api = self.veilid()?;
        let store = veilid_api.protected_store()?;
        Ok(store)
    }
}

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
            repos: HashMap::new(),
            iroh_blobs: None,
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
            repos: HashMap::new(),
            iroh_blobs: None,
        };

        let backend = Backend {
            inner: Arc::new(Mutex::new(inner)),
        };

        let inner_clone = backend.inner.clone();

        let on_new_route_callback: OnNewRouteCallback = Arc::new(move |_, _| {
            let inner = inner_clone.clone();
            tokio::spawn(async move {
                let inner = inner.lock().await;

                for group in inner.groups.clone().into_values().into_iter() {
                    if let Some(repo) = group.get_own_repo() {
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

        let (route_id, route_id_blob) = make_route(&veilid_api).await?;
        let routing_context = veilid_api.routing_context()?;

        let mut inner = backend.inner.lock().await;

        // Initialize iroh_blobs
        inner.iroh_blobs = Some(VeilidIrohBlobs::new(
            veilid_api.clone(),
            routing_context,
            route_id_blob,
            route_id,
            inner.update_rx.as_ref().unwrap().resubscribe(),
            store,
            None, // TODO: Notify application of route closure?
            Some(on_new_route_callback),
        ));

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

        let (veilid_api, mut update_rx) = init_veilid(&base_dir).await?;

        inner.veilid_api = Some(veilid_api.clone());
        inner.update_rx = Some(update_rx.resubscribe());

        // Initialize iroh_blobs store
        let store = iroh_blobs::store::fs::Store::load(base_dir.join("iroh")).await?;

        // Create route_id and route_id_blob
        let (route_id, route_id_blob) = make_route(&veilid_api).await?;

        // Get veilid_api and routing_context
        let routing_context = veilid_api.routing_context()?;

        let inner_clone = self.inner.clone();

        let on_new_route_callback: OnNewRouteCallback = Arc::new(move |_, _| {
            let inner = inner_clone.clone();
            tokio::spawn(async move {
                let inner = inner.lock().await;

                for group in inner.groups.clone().into_values().into_iter() {
                    if let Some(repo) = group.get_own_repo() {
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
        inner.iroh_blobs = Some(VeilidIrohBlobs::new(
            veilid_api.clone(),
            routing_context,
            route_id_blob,
            route_id,
            update_rx.resubscribe(),
            store,
            None, // TODO: Notify application of route closure?
            Some(on_new_route_callback),
        ));

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
            inner.repos = HashMap::new();
        }
        Ok(())
    }

    pub async fn join_from_url(&self, url_string: &str) -> Result<Box<Group>> {
        let keys = parse_url(url_string)?;
        self.join_group(keys).await
    }

    pub async fn join_group(&self, keys: CommonKeypair) -> Result<Box<Group>> {
        let mut inner = self.inner.lock().await;
        let routing_context = inner.veilid_api.as_ref().unwrap().routing_context()?;
        let crypto_system = CryptoSystemVLD0::new(inner.veilid_api.as_ref().unwrap().crypto()?);

        let record_key = TypedKey::new(CRYPTO_KIND_VLD0, keys.id);
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

        let group = Group {
            dht_record: dht_record.clone(),
            encryption_key: keys.encryption_key.clone(),
            routing_context,
            crypto_system,
            repos: Vec::new(),
            iroh_blobs: inner.iroh_blobs.clone(),
        };
        inner.groups.insert(group.id(), Box::new(group.clone()));

        inner.save_known_group_ids().await?;

        Ok(Box::new(group))
    }

    pub async fn create_group(&self) -> Result<Group> {
        let mut inner = self.inner.lock().await;

        let veilid = inner
            .veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API is not initialized"))?;
        let routing_context = veilid.routing_context()?;
        let schema = DHTSchema::dflt(3)?;
        let kind = Some(CRYPTO_KIND_VLD0);

        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let encryption_key = crypto_system.random_shared_secret();

        // Create an empty Iroh collection and get the root hash.
        let root_hash = self.create_collection().await?;

        // Set the root hash in the DHT record
        routing_context
            .set_dht_value(dht_record.key().clone(), 1, root_hash.to_hex().into(), None)
            .await
            .map_err(|e| anyhow!("Failed to store collection blob in DHT: {}", e))?;

        let group = Group::new(
            dht_record.clone(),
            encryption_key,
            routing_context,
            crypto_system,
            inner.iroh_blobs.clone(),
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

    pub async fn get_group(&self, record_key: TypedKey) -> Result<Box<Group>> {
        let mut inner = self.inner.lock().await;
        if let Some(group) = inner.groups.get(&record_key.value) {
            return Ok(group.clone());
        }

        let routing_context = inner.veilid_api.as_ref().unwrap().routing_context()?;
        let protected_store = inner
            .veilid_api
            .as_ref()
            .unwrap()
            .protected_store()
            .unwrap();

        // Load the keypair associated with the record_key from the protected store
        let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, &record_key.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?;

        let crypto_system = CryptoSystemVLD0::new(inner.veilid_api.as_ref().unwrap().crypto()?);

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
                    retrieved_keypair.secret_key.clone().unwrap(),
                )),
            )
            .await?;

        let group = Group {
            dht_record: dht_record.clone(),
            encryption_key: retrieved_keypair.encryption_key.clone(),
            routing_context,
            crypto_system,
            repos: Vec::new(),
            iroh_blobs: inner.iroh_blobs.clone(),
        };
        inner.groups.insert(group.id(), Box::new(group.clone()));

        drop(inner);

        let _ = self.join_group(retrieved_keypair).await;

        Ok(Box::new(group))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        let mut inner = self.inner.lock().await;
        Ok(inner.groups.values().cloned().collect())
    }

    pub async fn load_known_groups(self) -> Result<()> {
        for id in self.list_known_group_ids().await?.iter() {
            self.get_group(TypedKey::new(CRYPTO_KIND_VLD0, *id)).await?;
        }
        Ok(())
    }

    pub async fn list_known_group_ids(&self) -> Result<Vec<CryptoKey>> {
        let data = self
            .get_protected_store()
            .await?
            .load_user_secret(KNOWN_GROUP_LIST)
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?
            .ok_or_else(|| anyhow!("Keypair not found"))?;
        let info: KnownGroupList =
            serde_cbor::from_slice(&data).map_err(|_| anyhow!("Failed to deserialize keypair"))?;
        Ok(info.groups)
    }

    pub async fn close_group(&self, key: CryptoKey) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if let Some(group) = inner.groups.remove(&key) {
            group.close().await.map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!("Group not found"));
        }
        Ok(())
    }

    pub async fn get_protected_store(&self) -> Result<Arc<ProtectedStore>> {
        let mut inner = self.inner.lock().await;
        inner
            .veilid()
            .map(|api| Arc::new(api.protected_store().unwrap()))
    }

    pub async fn create_repo(&self, group_key: &CryptoKey) -> Result<Repo> {
        let mut inner = self.inner.lock().await;
        let veilid = inner.veilid()?;
        let routing_context = veilid.routing_context()?;

        let iroh_blobs = inner
            .iroh_blobs
            .as_ref()
            .ok_or_else(|| anyhow!("Iroh blobs not initialized"))?;

        // Retrieve the group from the Backend's groups map
        let group = inner
            .groups
            .get(group_key)
            .ok_or_else(|| anyhow!("Failed to retrieve group"))?
            .as_ref();

        // Check if the repo already exists
        if let Some(existing_repo) = inner.repos.get(&group.get_id()) {
            println!("Repo already exists with id: {}", existing_repo.get_id());
            return Ok(*existing_repo.clone());
        }

        // Create a new DHT record for the repo
        let schema = DHTSchema::dflt(3)?;
        let kind = Some(CRYPTO_KIND_VLD0);
        let repo_dht_record = routing_context.create_dht_record(schema, kind).await?;

        // Identify the repo with the DHT record's key
        let repo_id = repo_dht_record.key().clone();

        // Use the group's encryption key for the repo
        let encryption_key = group.get_encryption_key().clone();

        // Wrap the secret key in CryptoTyped for storage
        let secret_key_typed =
            CryptoTyped::new(CRYPTO_KIND_VLD0, group.get_secret_key().unwrap().clone());

        let repo = Repo::new(
            repo_dht_record.clone(),
            group.get_encryption_key().clone(),
            Some(secret_key_typed),
            routing_context,
            CryptoSystemVLD0::new(veilid.crypto()?),
            iroh_blobs.clone(),
        );

        // This should happen every time the route ID changes
        repo.update_route_on_dht().await?;

        // Store the repo's keypair in the protected store
        let protected_store = veilid.protected_store().unwrap();
        CommonKeypair {
            id: repo.id(),
            public_key: repo_dht_record.owner().clone(),
            secret_key: group.get_secret_key(),
            encryption_key: encryption_key.clone(),
        }
        .store_keypair(&protected_store)
        .await
        .map_err(|e| anyhow!(e))?;

        inner.repos.insert(repo.get_id(), Box::new(repo.clone()));

        Ok(repo)
    }

    pub async fn get_repo(&self, repo_id: TypedKey) -> Result<Box<Repo>> {
        let mut inner = self.inner.lock().await;
        if let Some(repo) = inner.repos.get(&repo_id.value) {
            return Ok(repo.clone());
        }

        let iroh_blobs = inner
            .iroh_blobs
            .as_ref()
            .ok_or_else(|| anyhow!("Iroh blobs not initialized"))?;

        let protected_store = inner.get_protected_store()?;

        // Load keypair using the repo ID
        let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, &repo_id.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair for repo_id: {:?}", repo_id))?;

        let routing_context = inner.veilid()?.routing_context()?;

        let dht_record = routing_context
            .open_dht_record(repo_id.clone(), None)
            .await?;

        let owner_key = dht_record.owner();
        // Reopen the DHT record with the owner key as the writer

        let dht_record = routing_context
            .open_dht_record(
                repo_id.clone(),
                Some(KeyPair::new(
                    owner_key.clone(),
                    retrieved_keypair.secret_key.clone().unwrap(),
                )),
            )
            .await?;

        let crypto_system = CryptoSystemVLD0::new(inner.veilid_api.as_ref().unwrap().crypto()?);

        let repo = Repo {
            dht_record,
            encryption_key: retrieved_keypair.encryption_key.clone(),
            secret_key: retrieved_keypair
                .secret_key
                .map(|sk| CryptoTyped::new(CRYPTO_KIND_VLD0, sk)),
            routing_context: routing_context,
            crypto_system,
            iroh_blobs: iroh_blobs.clone(),
        };

        // Cache the loaded repo for future access
        inner.repos.insert(repo.get_id(), Box::new(repo.clone()));

        Ok(Box::new(repo))
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

fn crypto_key_from_query(url: &Url, key: &str) -> Result<CryptoKey> {
    let value = find_query(url, key)?;
    let bytes = hex::decode(value)?;
    let mut key_vec: [u8; CRYPTO_KEY_LENGTH] = [0; CRYPTO_KEY_LENGTH];
    key_vec.copy_from_slice(bytes.as_slice());

    let key = CryptoKey::from(key_vec);
    Ok(key)
}

pub fn parse_url(url_string: &str) -> Result<CommonKeypair> {
    let url = Url::parse(url_string)?;

    let id = crypto_key_from_query(&url, URL_DHT_KEY)?;
    let encryption_key = crypto_key_from_query(&url, URL_ENCRYPTION_KEY)?;
    let public_key = crypto_key_from_query(&url, URL_PUBLIC_KEY)?;
    let secret_key = Some(crypto_key_from_query(&url, URL_SECRET_KEY)?);

    Ok(CommonKeypair {
        id,
        public_key,
        secret_key,
        encryption_key,
    })
}
