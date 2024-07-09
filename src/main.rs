use async_stream::stream;
use futures_core::stream::Stream;
use std::io::Result;
use veilid_core::CryptoKey;

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
}

impl DWebBackend {
    pub fn new(path: String, port: u16) -> Self {
        DWebBackend { path, port }
    }
    pub async fn start(&mut self) -> Result<()> {
        // Init veilid
        println!("Starting in {} with port {}", self.path, self.port);
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        println!("Stopping DWebBackend...");
        // Implementation of stopping logic goes here (async).
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
async fn main() -> Result<()> {
    let path = "./";
    let port = 8080;

    let mut d_web_backend = DWebBackend::new(String::from(path), port);

    // Start the backend and wait for SIGINT signal.
    d_web_backend.start().await?;

    // Stop the backend after receiving SIGINT signal.
    tokio::signal::ctrl_c().await?;

    d_web_backend.stop().await?;

    Ok(())
}
