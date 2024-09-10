use crate::common::DHTEntity;
use async_stream::stream;
use eyre::Result;
use futures_core::stream::Stream;
use std::sync::Arc;
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, RoutingContext, SharedSecret,
};

#[derive(Clone)]
pub struct Repo {
    pub id: CryptoKey,
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<CryptoTyped<CryptoKey>>,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
}

impl Repo {
    pub fn new(
        id: CryptoKey,
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<CryptoTyped<CryptoKey>>,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
    ) -> Self {
        Self {
            id,
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            crypto_system,
        }
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

impl DHTEntity for Repo {
    fn get_id(&self) -> CryptoKey {
        self.id.clone()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.encryption_key.clone()
    }

    fn get_routing_context(&self) -> Arc<RoutingContext> {
        self.routing_context.clone()
    }

    fn get_crypto_system(&self) -> CryptoSystemVLD0 {
        self.crypto_system.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.secret_key.clone().map(|key| key.value)
    }
}
