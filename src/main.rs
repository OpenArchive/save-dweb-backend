use async_stream::stream;
use futures_core::stream::Stream;
use iroh::docs::store::fs::Store;
use veilid_core::{VeilidAPI, CryptoKey, VeilidUpdate, VeilidConfigInner, api_startup_config, CRYPTO_KIND_VLD0, DHTSchema, CryptoTyped, DHTRecordDescriptor};
use std::sync::Arc;
use tokio::fs;
use tracing::info;
use eyre::{Result, anyhow};
use xdg::BaseDirectories;
use tmpdir::TmpDir;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

pub struct DataRepo {}

impl DataRepo {
    fn get_id(&self) -> CryptoKey {
        unimplemented!("WIP")
    }
    fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }
    fn file_names(&self) -> Result<Vec<String>> {
        unimplemented!("WIP")
    }
    async fn has_file(&self, file_name: &str) -> Result<bool> {
        unimplemented!("WIP")
    }
    async fn get_file_stream(&self, file_name: &str) -> Result<impl Stream<Item = Vec<u8>>> {
        let s = stream! {
            let mut vec: Vec<u8> = Vec::new();
            yield vec;
        };

        Ok(s)
    }
    async fn download_all(&self) -> Result<()> {
        unimplemented!("WIP")
    }
}

#[derive(Clone)]
pub struct Group {
    id: CryptoKey,
    dht_record: DHTRecordDescriptor,
    encryption_key: CryptoTyped<CryptoKey>,
    routing_context: Arc<veilid_core::RoutingContext>, // Store the routing context here
}

impl Group {
    // Able to find group on DHT
    pub fn get_id(&self) -> CryptoKey {
        self.id.clone()
    }
    // Able to add oneself to the group
    pub fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }
    // Able to read from group
    pub fn get_encryption_key(&self) -> CryptoKey {
        self.encryption_key.value
    }

    pub async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = &self.routing_context;
        let key = self.dht_record.key().clone();
        routing_context.set_dht_value(key, 0, name.as_bytes().to_vec(), None).await?;
        Ok(())
    }

    pub async fn get_name(&self) -> Result<String> {
        let routing_context = &self.routing_context;
        let key = self.dht_record.key().clone();
        let value = routing_context.get_dht_value(key, 0, false).await?;
        match value {
            Some(value) => Ok(String::from_utf8(value.data().to_vec()).map_err(|e| anyhow!("Failed to convert DHT value to string: {}", e))?),
            None => Err(anyhow!("Value not found"))
        }
    }

    pub async fn name(&self) -> Result<String> {
        self.get_name().await
    }

    pub async fn members(&self) -> Result<Vec<CryptoKey>> {
        unimplemented!("WIP")
    }

    pub async fn get_repo(&self, key: CryptoKey) -> Result<Box<DataRepo>> {
        unimplemented!("WIP")
    }

    pub async fn join(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    pub async fn leave(&self) -> Result<()> {
        unimplemented!("WIP")
    }
}

struct DWebBackend {
    path: PathBuf,
    port: u16,
    store: Store,
    veilid_api: Option<VeilidAPI>,
    groups: HashMap<CryptoKey, Box<Group>>,
}

impl DWebBackend {
    pub fn new(base_path: &Path, port: u16) -> Result<Self> {
        let store_path = base_path.join("store.db");
        let store = Store::persistent(&store_path).map_err(|e| anyhow!("Failed to create persistent store: {}", e))?;
        Ok(DWebBackend {
            path: base_path.to_path_buf(),
            port,
            store,
            veilid_api: None,
            groups: HashMap::new(),
        })
    }

    // Updated start method to initialize both Store and Veilid
    pub async fn start(&mut self) -> Result<()> {
        println!("Starting on {} with port {}", self.path.display(), self.port);

        // Ensure base directory exists
        let base_dir = &self.path;
        fs::create_dir_all(base_dir).await.map_err(|e| {
            anyhow!("Failed to create base directory {}: {}", base_dir.display(), e)
        })?;

        // Initialize Veilid
        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(|update| {
            info!("Received update: {:?}", update);
        });

        let xdg_dirs = BaseDirectories::with_prefix("save-dweb-backend")?;
        let base_dir = xdg_dirs.get_data_home();

        // Create a VeilidConfigInner instance
        let config_inner = VeilidConfigInner {
            program_name: "save-dweb-backend".to_string(),
            namespace: "openarchive".into(), 
            capabilities: Default::default(),
            protected_store: veilid_core::VeilidConfigProtectedStore {
                // avoid prompting for password, don't do this in production
                allow_insecure_fallback: true,
                always_use_insecure_storage: true,
                directory: base_dir.join("protected_store").to_string_lossy().to_string(),
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

        self.veilid_api = Some(api_startup_config(update_callback, config_inner).await.map_err(|e| {
            anyhow!("Failed to initialize Veilid API: {}", e)
        })?);

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        println!("Stopping DWebBackend...");
        if let Some(veilid) = &self.veilid_api {
            veilid.clone().shutdown().await;
        }
        Ok(())
    }

    pub async fn create_group(&mut self) -> Result<()> {
        let veilid = self.veilid_api.as_ref().ok_or_else(|| anyhow!("Veilid API is not initialized"))?;
        let routing_context = veilid.routing_context()?;
        let schema = DHTSchema::dflt(1)?;
        let kind = Some(CRYPTO_KIND_VLD0);

        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let encryption_key = CryptoTyped::new(CRYPTO_KIND_VLD0, CryptoKey::new([0; 32]));

        let group = Group {
            id: encryption_key.value,
            dht_record,
            encryption_key,
            routing_context: Arc::new(routing_context), // Store routing context in group
        };

        self.groups.insert(group.get_id(), Box::new(group));

        Ok(())
    }

    pub async fn get_group(&self, key: CryptoKey) -> Result<Box<Group>> {
        self.groups.get(&key).cloned().ok_or_else(|| anyhow!("Group not found"))
    }

    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        Ok(self.groups.values().cloned().collect())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = xdg::BaseDirectories::with_prefix("save-dweb-backend")?.get_data_home();
    let port = 8080;

    // Ensure the directory exists before creating the store
    fs::create_dir_all(&path).await.expect("Failed to create base directory");

    let mut d_web_backend = DWebBackend::new(&path, port)?;

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await?;

    // Create a group
    d_web_backend.create_group().await?;

    // Stop the backend after receiving SIGINT signal.
    tokio::signal::ctrl_c().await?;

    d_web_backend.stop().await?;

    Ok(())
}

#[tokio::test]
async fn basic_test() {
    let path = TmpDir::new("test_dweb_backend").await.unwrap();
    let port = 8080;

    // Ensure the directory exists before creating the store
    fs::create_dir_all(path.as_ref()).await.expect("Failed to create base directory");

    let mut d_web_backend = DWebBackend::new(path.as_ref(), port).expect("Unable to create DWebBackend");

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await.expect("Unable to start");
    d_web_backend.create_group().await.expect("Unable to create group");

    // Set and get group name
    let group_key = d_web_backend.groups.keys().next().cloned().expect("Group not found");
    let group = d_web_backend.get_group(group_key.clone()).await.expect("Group not found");
    group.set_name("Test Group").await.expect("Unable to set group name");
    let name = group.get_name().await.expect("Unable to get group name");
    assert_eq!(name, "Test Group");

    d_web_backend.stop().await.expect("Unable to stop");
}
