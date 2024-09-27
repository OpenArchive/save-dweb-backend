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

    pub async fn download_blob(
        &self,
        veilid_api: &VeilidAPI,
        update_rx: &mut broadcast::Receiver<VeilidUpdate>,
        route_id_blob: Vec<u8>,
        hash: &Hash,
    ) -> Result<()> {
        // Import the remote route
        let route_id = veilid_api.import_remote_private_route(route_id_blob.clone())?;

        // Obtain the RoutingContext
        let routing_context = veilid_api.routing_context()?;

        // Send the ASK command
        let mut to_send = BytesMut::with_capacity(hash.as_bytes().len() + 1);
        to_send.put_u8(ASK);
        to_send.put(&hash.as_bytes()[..]);

        let target = Target::PrivateRoute(route_id);
        routing_context.app_message(target, to_send.to_vec()).await?;

        println!("Sent ASK command, waiting for response");

        // Set up a channel to collect incoming data
        let (send_file, read_file) = mpsc::channel::<std::io::Result<Bytes>>(2);

        // Clone variables for the spawned task
        let mut update_rx_clone = update_rx.resubscribe();
        let route_id_clone = route_id;
        let send_file_clone = send_file.clone();

        // Spawn a task to handle incoming messages
        tokio::spawn(async move {
            while let Ok(update) = update_rx_clone.recv().await {
                if let VeilidUpdate::AppMessage(app_message) = update {
                    // Check if the message is from the expected route
                    if let Some(sender_route_id) = app_message.route_id() {
                        if sender_route_id == &route_id_clone {
                            let message = app_message.message();
                            if message.len() < 1 {
                                let _ = send_file_clone
                                    .send(Err(std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "Received empty message",
                                    )))
                                    .await;
                                return;
                            }

                            let command = message[0];

                            if command == DONE {
                                break;
                            } else if command == DATA {
                                let bytes = Bytes::copy_from_slice(&message[1..]);
                                if let Err(_) = send_file_clone.send(Ok(bytes)).await {
                                    return;
                                }
                            } else if command == ERR {
                                let _ = send_file_clone
                                    .send(Err(std::io::Error::new(
                                        ErrorKind::Other,
                                        "Error from peer",
                                    )))
                                    .await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        // Use `iroh_blobs` to upload from stream
        if let Some(iroh_blobs) = &self.iroh_blobs {
            let got_hash = iroh_blobs.upload_from_stream(read_file).await?;

            if got_hash.eq(hash) {
                return Ok(());
            } else {
                // Handle hash mismatch if necessary
                return Err(anyhow!("Peer returned invalid hash {}", got_hash));
            }
        } else {
            return Err(anyhow!("iroh_blobs not initialized"));
        }
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
