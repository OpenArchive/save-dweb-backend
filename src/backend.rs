use crate::common::{make_route, CommonKeypair, DHTEntity};
use crate::group::{Group, URL_DHT_KEY, URL_ENCRYPTION_KEY, URL_PUBLIC_KEY, URL_SECRET_KEY};
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use clap::builder::Str;
use iroh::node::Node;
use iroh_blobs::format::collection::Collection;
use iroh_blobs::util::SetTagOption;
use iroh_blobs::Hash;
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
use xdg::BaseDirectories;

pub struct BackendInner {
    path: PathBuf,
    veilid_api: Option<VeilidAPI>,
    update_rx: Option<broadcast::Receiver<VeilidUpdate>>,
    groups: HashMap<CryptoKey, Box<Group>>,
    repos: HashMap<CryptoKey, Box<Repo>>,
    pub iroh_blobs: Option<VeilidIrohBlobs>,
}

pub struct Backend {
    inner: Arc<Mutex<BackendInner>>,
}

impl Backend {
    pub fn new(base_path: &Path, port: u16) -> Result<Self> {
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

    pub async fn start(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        println!("Starting on {}", inner.path.display());

        let base_dir = &inner.path;
        fs::create_dir_all(base_dir).await.map_err(|e| {
            anyhow!(
                "Failed to create base directory {}: {}",
                base_dir.display(),
                e
            )
        })?;

        let (update_tx, update_rx) = broadcast::channel::<VeilidUpdate>(32);

        let update_callback: UpdateCallback = Arc::new(move |update| {
            let update_tx = update_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = update_tx.send(update) {
                    println!("Failed to send update: {}", e);
                }
            });
        });

        let xdg_dirs = BaseDirectories::with_prefix("save-dweb-backend")?;
        let base_dir = xdg_dirs.get_data_home();

        let config_inner = VeilidConfigInner {
            program_name: "save-dweb-backend".to_string(),
            namespace: "openarchive".into(),
            capabilities: Default::default(),
            protected_store: veilid_core::VeilidConfigProtectedStore {
                allow_insecure_fallback: true,
                always_use_insecure_storage: true,
                directory: base_dir
                    .join("protected_store")
                    .to_string_lossy()
                    .to_string(),
                delete: false,
                device_encryption_key_password: "".to_string(),
                new_device_encryption_key_password: None,
            },
            table_store: veilid_core::VeilidConfigTableStore {
                directory: base_dir.join("table_store").to_string_lossy().to_string(),
                delete: false,
            },
            block_store: veilid_core::VeilidConfigBlockStore {
                directory: base_dir.join("block_store").to_string_lossy().to_string(),
                delete: false,
            },
            network: Default::default(),
        };

        if inner.veilid_api.is_none() {
            let veilid_api = api_startup_config(update_callback, config_inner)
                .await
                .map_err(|e| anyhow!("Failed to initialize Veilid API: {}", e))?;
            inner.veilid_api = Some(veilid_api);
        } else {
            return Err(anyhow!("Veilid already initialized"));
        }

        inner.veilid_api.clone().unwrap().attach().await?;

        println!("Waiting for network ready state");

        inner.update_rx = Some(update_rx);

        // Wait for network ready state
        if let Some(rx) = &inner.update_rx {
            wait_for_network(rx.resubscribe()).await?;
        }

        // Initialize iroh_blobs store
        let store = iroh_blobs::store::fs::Store::load(inner.path.join("iroh")).await?;

        // Get veilid_api and routing_context
        let veilid_api = inner.veilid_api.clone().unwrap();
        let routing_context = veilid_api.routing_context()?;

        // Create route_id and route_id_blob
        let (route_id, route_id_blob) = make_route(&veilid_api).await?;

        // Initialize iroh_blobs
        inner.iroh_blobs = Some(VeilidIrohBlobs::new(
            veilid_api.clone(),
            routing_context,
            route_id_blob,
            route_id,
            inner.update_rx.as_ref().unwrap().resubscribe(),
            store,
            None,
            None,
        ));

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
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
            routing_context: Arc::new(routing_context),
            crypto_system,
            repos: Vec::new(),
            iroh_blobs: inner.iroh_blobs.clone(),
        };
        inner.groups.insert(group.id(), Box::new(group.clone()));

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
            Arc::new(routing_context),
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
            routing_context: Arc::new(routing_context),
            crypto_system,
            repos: Vec::new(),
            iroh_blobs: inner.iroh_blobs.clone(),
        };
        inner.groups.insert(group.id(), Box::new(group.clone()));

        let _ = self.join_group(retrieved_keypair).await;

        Ok(Box::new(group))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        let mut inner = self.inner.lock().await;
        Ok(inner.groups.values().cloned().collect())
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
            .veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API not initialized"))
            .map(|api| Arc::new(api.protected_store().unwrap()))
    }

    pub async fn create_repo(&self, group_key: &CryptoKey) -> Result<Repo> {
        let mut inner = self.inner.lock().await;
        let veilid = inner
            .veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API is not initialized"))?;
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
            Arc::new(routing_context),
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

        let protected_store = inner
            .veilid_api
            .as_ref()
            .unwrap()
            .protected_store()
            .unwrap();

        // Load keypair using the repo ID
        let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, &repo_id.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair for repo_id: {:?}", repo_id))?;
        let routing_context = inner.veilid_api.as_ref().unwrap().routing_context()?;
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
            routing_context: Arc::new(routing_context),
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

async fn wait_for_network(mut update_rx: broadcast::Receiver<VeilidUpdate>) -> Result<()> {
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
