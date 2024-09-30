use crate::common::DHTEntity;
use async_stream::stream;
use anyhow::{Result, anyhow};
use futures_core::stream::Stream;
use std::sync::Arc;
use std::io::ErrorKind;
use tokio::sync::{mpsc, broadcast};
use bytes::{Bytes, BytesMut, BufMut};
use veilid_core::{
    CryptoKey, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, RoutingContext, SharedSecret, VeilidAPI, Target, VeilidUpdate,
};
use iroh_blobs::Hash;
use veilid_iroh_blobs::iroh::VeilidIrohBlobs;

use crate::constants::{ASK, DATA, DONE, YES, NO, ERR};

#[derive(Clone)]
pub struct Repo {
    pub id: CryptoKey,
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<CryptoTyped<CryptoKey>>,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
    pub iroh_blobs: Option<VeilidIrohBlobs>,
}

impl Repo {
    pub fn new(
        id: CryptoKey,
        dht_record: DHTRecordDescriptor,
        encryption_key: SharedSecret,
        secret_key: Option<CryptoTyped<CryptoKey>>,
        routing_context: Arc<RoutingContext>,
        crypto_system: CryptoSystemVLD0,
        iroh_blobs: Option<VeilidIrohBlobs>,
    ) -> Self {
        Self {
            id,
            dht_record,
            encryption_key,
            secret_key,
            routing_context,
            crypto_system,
            iroh_blobs,
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

    fn get_route_id_blob(&self) -> Vec<u8> {
        self.iroh_blobs.as_ref().expect("iroh_blobs not initialized").route_id_blob()
    }
}
