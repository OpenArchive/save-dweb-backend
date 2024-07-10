use async_stream::stream;
use futures_core::stream::Stream;
use iroh::docs::{store::fs::Store, NamespaceId, NamespaceSecret, Replica};
use std::io::Result;
use veilid_core::{VeilidAPI, VeilidUpdate, VeilidConfigInner, api_startup_config};
use std::sync::Arc;
use tokio::fs;
use tracing::info;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};


pub struct Group<'a> {
    id: NamespaceId,
    replica: Replica<'a>,
    secret: Option<NamespaceSecret>,
}

impl Group<'_> {
    pub fn members(&self) -> Option<Vec<NamespaceId>> {
        Some(vec![]) // Assuming this method would return an empty list for now. Replace it with the actual logic to retrieve members' NamespaceIds.
    }
}
trait DataRepo {
    fn file_names(&self) -> Result<Vec<String>>;
    async fn has_file(&self, file_name: &str) -> Result<bool>;
    async fn get_file_stream(&self, file_name: &str) -> Result<impl Stream<Item = Vec<u8>>>;
    fn get_id(&self) -> NamespaceId;
}

trait PersonalDataRepo: DataRepo {}

pub struct DWebBackend {
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
