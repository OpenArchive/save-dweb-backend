use crate::common::{CommonKeypair, DHTEntity, make_route};
use crate::group::Group;
use crate::repo::Repo;
use anyhow::{anyhow, Result};
use iroh_blobs::Hash;
use std::collections::HashMap;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{mpsc::{self, Receiver}, oneshot, broadcast};
use tracing::info;
use veilid_core::{
    api_startup_config, vld0_generate_keypair, CryptoKey, CryptoSystem, CryptoSystemVLD0,
    CryptoTyped, DHTSchema, KeyPair, ProtectedStore, RoutingContext, SharedSecret, UpdateCallback,
    VeilidAPI, VeilidConfigInner, VeilidUpdate, CRYPTO_KIND_VLD0, TypedKey, VeilidConfigProtectedStore
};
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;
use xdg::BaseDirectories;

pub struct Backend {
    path: PathBuf,
    port: u16,
    veilid_api: Option<VeilidAPI>,
    update_rx: Option<broadcast::Receiver<VeilidUpdate>>,
    groups: HashMap<CryptoKey, Box<Group>>,
    repos: HashMap<CryptoKey, Box<Repo>>,
    iroh_blobs: Option<VeilidIrohBlobs>,
}

impl Backend {
    pub fn new(base_path: &Path, port: u16) -> Result<Self> {
        Ok(Backend {
            path: base_path.to_path_buf(),
            port,
            veilid_api: None,
            update_rx: None, 
            groups: HashMap::new(),
            repos: HashMap::new(),
            iroh_blobs: None,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        println!(
            "Starting on {} with port {}",
            self.path.display(),
            self.port
        );
        let base_dir = &self.path;
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
    
        if self.veilid_api.is_none() {
            let veilid_api = api_startup_config(update_callback, config_inner)
                .await
                .map_err(|e| anyhow!("Failed to initialize Veilid API: {}", e))?;
            self.veilid_api = Some(veilid_api);
        } else {
            return Err(anyhow!("Veilid already initialized"));
        }
    
        self.veilid_api.clone().unwrap().attach().await?;
    
        println!("Waiting for network ready state");
    
        self.update_rx = Some(update_rx);
    
        // Wait for network ready state
        if let Some(rx) = &self.update_rx {
            self.wait_for_network(rx.resubscribe()).await?;
        }
    
        // Initialize iroh_blobs store
        let store = iroh_blobs::store::fs::Store::load(self.path.join("iroh")).await?;
    
        // Get veilid_api and routing_context
        let veilid_api = self.veilid_api.clone().unwrap();
        let routing_context = veilid_api.routing_context()?;
    
        // Create route_id and route_id_blob
        let (route_id, route_id_blob) = make_route(&veilid_api).await?;
    
        // Initialize iroh_blobs
        self.iroh_blobs = Some(VeilidIrohBlobs::new(
            veilid_api.clone(),
            routing_context,
            route_id_blob,
            route_id,
            self.update_rx.as_ref().unwrap().resubscribe(),
            store,
        ));
    
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        println!("Stopping Backend...");
        if let Some(iroh_blobs) = self.iroh_blobs.take() {
            println!("Shutting down Veilid Iroh Blobs");
            iroh_blobs.shutdown().await?;
            println!("Veilid Iroh Blobs shut down successfully");
        }
        if self.veilid_api.is_some() {
            println!("Shutting down Veilid API");
            let veilid = self.veilid_api.take();
            veilid.unwrap().shutdown().await;
            println!("Veilid API shut down successfully");
            self.groups = HashMap::new();
            self.repos = HashMap::new();
        }
        Ok(())
    }

    async fn wait_for_network(&self, mut update_rx: broadcast::Receiver<VeilidUpdate>) -> Result<()> {
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
    
    pub async fn create_group(&mut self) -> Result<Group> {
        let veilid = self
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
    
        let group = Group::new(
            dht_record.clone(),
            encryption_key,
            Arc::new(routing_context),
            crypto_system,
            self.iroh_blobs.clone(),
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
    
        self.groups.insert(group.id(), Box::new(group.clone()));
    
        Ok(group)
    }

    pub async fn get_group(&mut self, record_key: TypedKey) -> Result<Box<Group>> {
        if let Some(group) = self.groups.get(&record_key.value) {
            return Ok(group.clone());
        }
    
        let routing_context = self.veilid_api.as_ref().unwrap().routing_context()?;
        let protected_store = self.veilid_api.as_ref().unwrap().protected_store().unwrap();
    
        // Load the keypair associated with the record_key from the protected store
        let retrieved_keypair = CommonKeypair::load_keypair(&protected_store, &record_key.value)
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?;

        let crypto_system = CryptoSystemVLD0::new(self.veilid_api.as_ref().unwrap().crypto()?);
    
        // First open the DHT record
        let dht_record = routing_context
            .open_dht_record(record_key.clone(), None) // Don't pass a writer here yet
            .await?;
        
        // Use the owner key from the DHT record as the default writer
        let owner_key = dht_record.owner(); // Call the owner() method to get the owner key
    
        // Reopen the DHT record with the owner key as the writer
        let dht_record = routing_context
            .open_dht_record(record_key.clone(), Some(KeyPair::new(owner_key.clone(), retrieved_keypair.secret_key.clone().unwrap())))
            .await?;
    
    
        let group = Group {
            dht_record: dht_record.clone(),
            encryption_key: retrieved_keypair.encryption_key.clone(),
            routing_context: Arc::new(routing_context),
            crypto_system,
            repos: Vec::new(),
            iroh_blobs: self.iroh_blobs.clone(),
        };
        self.groups.insert(group.id(), Box::new(group.clone()));
    
        Ok(Box::new(group))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        Ok(self.groups.values().cloned().collect())
    }

    pub async fn close_group(&mut self, key: CryptoKey) -> Result<()> {
        if let Some(group) = self.groups.remove(&key) {
            group.close().await.map_err(|e| anyhow!(e))?;
        } else {
            return Err(anyhow!("Group not found"));
        }
        Ok(())
    }

    pub fn get_protected_store(&self) -> Result<Arc<ProtectedStore>> {
        self.veilid_api
            .as_ref()
            .ok_or_else(|| anyhow!("Veilid API not initialized"))
            .map(|api| Arc::new(api.protected_store().unwrap()))
    }

    pub async fn create_repo(&mut self) -> Result<Repo> {
        let veilid = self
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

        let repo = Repo::new(
            keypair.key.clone(),
            dht_record,
            encryption_key,
            Some(CryptoTyped::new(CRYPTO_KIND_VLD0, keypair.secret)),
            Arc::new(routing_context),
            crypto_system,
            self.iroh_blobs.clone(),
        );

        self.repos.insert(repo.get_id(), Box::new(repo.clone()));

        Ok(repo)
    }

    pub async fn get_repo(&self, key: CryptoKey) -> Result<Box<Repo>> {
        if let Some(repo) = self.repos.get(&key) {
            return Ok(repo.clone());
        }

        let protected_store = self.veilid_api.as_ref().unwrap().protected_store().unwrap();
        let keypair_data = protected_store
            .load_user_secret(key.to_string())
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?
            .ok_or_else(|| anyhow!("Keypair not found"))?;
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data)
            .map_err(|_| anyhow!("Failed to deserialize keypair"))?;

        let routing_context = self.veilid_api.as_ref().unwrap().routing_context()?;
        let dht_record = if let Some(secret_key) = retrieved_keypair.secret_key.clone() {
            routing_context
                .open_dht_record(
                    CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()),
                    Some(KeyPair {
                        key: retrieved_keypair.public_key.clone(),
                        secret: secret_key,
                    }),
                )
                .await?
        } else {
            routing_context
                .open_dht_record(
                    CryptoTyped::new(CRYPTO_KIND_VLD0, retrieved_keypair.public_key.clone()),
                    None,
                )
                .await?
        };

        let crypto_system = CryptoSystemVLD0::new(self.veilid_api.as_ref().unwrap().crypto()?);

        let repo = Repo {
            id: retrieved_keypair.public_key.clone(),
            dht_record,
            encryption_key: SharedSecret::new([0; 32]),
            secret_key: retrieved_keypair
                .secret_key
                .map(|sk| CryptoTyped::new(CRYPTO_KIND_VLD0, sk)),
            routing_context: Arc::new(routing_context),
            crypto_system,
            iroh_blobs: self.iroh_blobs.clone(),
        };

        Ok(Box::new(repo))
    }

    pub fn subscribe_updates(&self) -> Option<broadcast::Receiver<VeilidUpdate>> {
        self.update_rx.as_ref().map(|rx| rx.resubscribe())
    }    

    pub fn get_veilid_api(&self) -> Option<&VeilidAPI> {
        self.veilid_api.as_ref()
    }
}
