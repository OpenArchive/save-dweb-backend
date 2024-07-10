use async_stream::stream;
use futures_core::stream::Stream;
use std::io::Result;
use iroh::docs::{store::fs::Store, NamespaceId, NamespaceSecret, Replica};
use veilid_core::{VeilidAPI, CryptoKey, VeilidUpdate, VeilidConfigInner, api_startup_config};
use std::sync::Arc;
use tokio::fs;
use tracing::info;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

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

pub struct Group {}
impl Group {
    // Able to find group on DHT
    pub fn get_id(&self) -> CryptoKey {
        unimplemented!("WIP")
    }
    // Able to add oneself to the group
    pub fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }
    // Able to read from group
    pub fn get_encryption_key(&self) -> CryptoKey {
        unimplemented!("WIP")
    }

    pub async fn name(&self) -> Result<String> {
        unimplemented!("WIP")
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
    path: String,
    port: u16,
    store: Store,
    veilid_api: Option<VeilidAPI>,
}

impl DWebBackend {
    pub fn new(base_path: &str, port: u16) -> Self {
        let store_path = format!("{}/store.db", base_path);
        let store = Store::persistent(&store_path).expect("Failed to create persistent store");
        DWebBackend {
            path: base_path.to_string(),
            port,
            store,
            veilid_api: None,
        }
    }

    // Updated start method to initialize both Store and Veilid
    pub async fn start(&mut self) -> eyre::Result<()> {
        println!("Starting on {} with port {}", self.path, self.port);

        // Ensure base directory exists
        let base_dir = &self.path;
        fs::create_dir_all(base_dir).await.map_err(|e| {
            eyre::eyre!("Failed to create base directory {}: {}", base_dir, e)
        })?;

        // Initialize Veilid
        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(|update| {
            info!("Received update: {:?}", update);
        });

        let mut rng = StdRng::from_entropy();
        let random_suffix: u16 = rng.gen_range(10000..60000);

        // Create a VeilidConfigInner instance
        let config_inner = VeilidConfigInner {
            program_name: format!("node{}", random_suffix),
            namespace: format!("default_{}", random_suffix),
            capabilities: Default::default(),
            protected_store: veilid_core::VeilidConfigProtectedStore {
                allow_insecure_fallback: true,
                always_use_insecure_storage: true,
                directory: format!("{}/protected_store_{}", base_dir, random_suffix),
                delete: false,
                device_encryption_key_password: "".to_string(),
                new_device_encryption_key_password: None,
            },
            table_store: veilid_core::VeilidConfigTableStore {
                directory: format!("{}/table_store_{}", base_dir, random_suffix),
                delete: false,
            },
            block_store: veilid_core::VeilidConfigBlockStore {
                directory: format!("{}/block_store_{}", base_dir, random_suffix),
                delete: false,
            },
            network: Default::default(),
        };

        self.veilid_api = Some(api_startup_config(update_callback, config_inner).await.map_err(|e| {
            eyre::eyre!("Failed to initialize Veilid API: {}", e)
        })?);

        Ok(())
    }

    pub async fn stop(&self) -> eyre::Result<()> {
        println!("Stopping DWebBackend...");
        if let Some(veilid) = &self.veilid_api {
            veilid.clone().shutdown().await;
        }
        Ok(())
    }

    pub async fn get_group(&self, key: CryptoKey) -> Result<Box<Group>> {
        unimplemented!("WIP")
    }
    pub async fn list_groups(&self) -> Result<Vec<Box<Group>>> {
        unimplemented!("WIP")
    }
}

#[tokio::test]
async fn basic_test() {
    let path = "./";
    let port = 8080;

    let mut d_web_backend = DWebBackend::new(String::from(path), port);

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await.expect("Unable to start");
    d_web_backend.stop().await.expect("Unable to stop");
}


#[tokio::main]
async fn main() -> eyre::Result<()> {
    let path = "./tmp/save_dweb_backend"; // Changed to use a relative temporary directory
    let port = 8080;

    // Ensure the directory exists before creating the store
    fs::create_dir_all(path).await.expect("Failed to create base directory");

    let mut d_web_backend = DWebBackend::new(path, port);

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await?;

    // Stop the backend after receiving SIGINT signal.
    tokio::signal::ctrl_c().await?;

    d_web_backend.stop().await?;

    Ok(())
}

#[tokio::test]
async fn basic_test() {
    let path = "./tmp/test_dweb_backend";
    let port = 8080;

    // Ensure the directory exists before creating the store
    fs::create_dir_all(path).await.expect("Failed to create base directory");

    let mut d_web_backend = DWebBackend::new(path, port);

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await.expect("Unable to start");
    d_web_backend.stop().await.expect("Unable to stop");
}
