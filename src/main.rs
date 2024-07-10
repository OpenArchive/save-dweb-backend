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
    port: u16,
    store: Store,
}

impl DWebBackend {
    pub fn new(path: &str, port: u16) -> Self {
        let d_web_backend = DWebBackend {
            port,
            path: path.to_string(),
        };
        d_web_backend
    }

    pub async fn start(&mut self) -> Result<()> {
        println!("Starting on {} with port {}", self.path, self.port);
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        println!("Stopping DWebBackend...");
        // Implementation of stopping logic goes here (async).
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let path = "/api";
    let port = 8080;

    let mut d_web_backend = DWebBackend::new(&path, port);

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await?;

    // Stop the backend after receiving SIGINT signal.
    tokio::signal::ctrl_c().await?;

    d_web_backend.stop().await?;

    Ok(())
}
