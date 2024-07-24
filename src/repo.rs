use async_stream::stream;
use futures_core::stream::Stream;
use eyre::Result;
use veilid_core::CryptoKey;

pub struct Repo {}

impl Repo {
    pub fn new() -> Self {
        Self {}
    }

    pub fn get_id(&self) -> CryptoKey {
        unimplemented!("WIP")
    }

    pub fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }

    pub fn file_names(&self) -> Result<Vec<String>> {
        unimplemented!("WIP")
    }

    pub async fn has_file(&self, file_name: &str) -> Result<bool> {
        unimplemented!("WIP")
    }

    pub async fn get_file_stream(&self, file_name: &str) -> Result<impl Stream<Item = Vec<u8>>> {
        let s = stream! {
            let mut vec: Vec<u8> = Vec::new();
            yield vec;
        };

        Ok(s)
    }

    pub async fn download_all(&self) -> Result<()> {
        unimplemented!("WIP")
    }
}
