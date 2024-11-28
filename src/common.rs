#![allow(async_fn_in_trait)]
#![allow(clippy::async_yields_async)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{path::Path, path::PathBuf, sync::Arc};
use tokio::sync::broadcast::{self, Receiver};
use url::Url;
use veilid_core::{
    CryptoKey, CryptoSystem, CryptoSystemVLD0, CryptoTyped, DHTRecordDescriptor, KeyPair, Nonce,
    ProtectedStore, RouteId, RoutingContext, Sequencing, SharedSecret, Stability, UpdateCallback,
    VeilidAPI, VeilidConfigInner, VeilidUpdate, CRYPTO_KIND_VLD0, VALID_CRYPTO_KINDS,
};

use crate::constants::ROUTE_ID_DHT_KEY;

pub async fn make_route(veilid: &VeilidAPI) -> Result<(RouteId, Vec<u8>)> {
    let mut retries = 6;
    while retries > 0 {
        retries -= 1;
        let result = veilid
            .new_custom_private_route(
                &VALID_CRYPTO_KINDS,
                Stability::Reliable,
                Sequencing::PreferOrdered,
            )
            .await;

        if let Ok(value) = result {
            return Ok(value);
        } else if let Err(e) = &result {
            eprintln!("Failed to create route: {}", e);
        }
    }
    Err(anyhow!("Unable to create route, reached max retries"))
}

pub async fn init_veilid(
    base_dir: &Path,
    namespace: String,
) -> Result<(VeilidAPI, Receiver<VeilidUpdate>)> {
    let config_inner = config_for_dir(base_dir.to_path_buf(), namespace);

    let (tx, mut rx) = broadcast::channel(32);

    let update_callback: UpdateCallback = Arc::new(move |update| {
        let tx = tx.clone();
        tokio::spawn(async move {
            if tx.send(update).is_err() {
                // TODO:
                //println!("receiver dropped");
            }
        });
    });

    // println!("Init veilid");
    let veilid = veilid_core::api_startup_config(update_callback, config_inner).await?;

    //println!("Attach veilid");

    veilid.attach().await?;

    //println!("Wait for veilid network");

    while let Ok(update) = rx.recv().await {
        if let VeilidUpdate::Attachment(attachment_state) = update {
            if attachment_state.public_internet_ready && attachment_state.state.is_attached() {
                println!("Public internet ready!");
                break;
            }
        }
    }

    Ok((veilid, rx))
}

pub fn config_for_dir(base_dir: PathBuf, namespace: String) -> VeilidConfigInner {
    VeilidConfigInner {
        program_name: "save-dweb-backend".to_string(),
        namespace,
        protected_store: veilid_core::VeilidConfigProtectedStore {
            // avoid prompting for password, don't do this in production
            always_use_insecure_storage: true,
            directory: base_dir
                .join("protected_store")
                .to_string_lossy()
                .to_string(),
            ..Default::default()
        },
        table_store: veilid_core::VeilidConfigTableStore {
            directory: base_dir.join("table_store").to_string_lossy().to_string(),
            ..Default::default()
        },
        block_store: veilid_core::VeilidConfigBlockStore {
            directory: base_dir.join("block_store").to_string_lossy().to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommonKeypair {
    pub id: CryptoKey,
    pub public_key: CryptoKey,
    pub secret_key: Option<CryptoKey>,
    pub encryption_key: SharedSecret,
}

impl CommonKeypair {
    pub async fn store_keypair(&self, protected_store: &ProtectedStore) -> Result<()> {
        let keypair_data =
            serde_cbor::to_vec(&self).map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;
        protected_store
            .save_user_secret(self.id.to_string(), &keypair_data)
            .await
            .map_err(|e| anyhow!("Unable to store keypair: {}", e))?;
        Ok(())
    }

    pub async fn load_keypair(protected_store: &ProtectedStore, id: &CryptoKey) -> Result<Self> {
        let keypair_data = protected_store
            .load_user_secret(id.to_string())
            .await
            .map_err(|_| anyhow!("Failed to load keypair"))?
            .ok_or_else(|| anyhow!("Keypair not found"))?;
        let retrieved_keypair: CommonKeypair = serde_cbor::from_slice(&keypair_data)
            .map_err(|_| anyhow!("Failed to deserialize keypair"))?;
        Ok(retrieved_keypair)
    }
}

pub trait DHTEntity {
    fn get_id(&self) -> CryptoKey;
    fn get_encryption_key(&self) -> SharedSecret;
    fn get_routing_context(&self) -> RoutingContext;
    fn get_crypto_system(&self) -> CryptoSystemVLD0;
    fn get_dht_record(&self) -> DHTRecordDescriptor;
    fn get_secret_key(&self) -> Option<CryptoKey>;

    // Default method to get the owner key
    fn owner_key(&self) -> CryptoKey {
        self.get_dht_record().owner().clone()
    }

    // Default method to get the owner secret
    fn owner_secret(&self) -> Option<CryptoKey> {
        self.get_dht_record().owner_secret().cloned()
    }

    fn encrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = self.get_crypto_system().random_nonce();
        let mut buffer = Vec::with_capacity(nonce.as_slice().len() + data.len());
        buffer.extend_from_slice(nonce.as_slice());
        buffer.extend_from_slice(
            &self
                .get_crypto_system()
                .encrypt_aead(data, &nonce, &self.get_encryption_key(), associated_data)
                .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?,
        );
        Ok(buffer)
    }

    fn decrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = data[..24]
            .try_into()
            .map_err(|_| anyhow!("Failed to convert nonce slice to array"))?;
        let nonce = Nonce::new(nonce);
        let encrypted_data = &data[24..];
        self.get_crypto_system()
            .decrypt_aead(
                encrypted_data,
                &nonce,
                &self.get_encryption_key(),
                associated_data,
            )
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))
    }

    async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let encrypted_name = self.encrypt_aead(name.as_bytes(), None)?;
        routing_context
            .set_dht_value(key, 0, encrypted_name, None)
            .await?;
        Ok(())
    }

    async fn get_name(&self) -> Result<String> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let value = routing_context.get_dht_value(key, 0, false).await?;
        match value {
            Some(value) => {
                let decrypted_name = self.decrypt_aead(value.data(), None)?;
                Ok(String::from_utf8(decrypted_name)
                    .map_err(|e| anyhow!("Failed to convert DHT value to string: {}", e))?)
            }
            None => Err(anyhow!("Value not found")),
        }
    }

    async fn close(&self) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        routing_context.close_dht_record(key).await?;
        Ok(())
    }

    async fn store_route_id_in_dht(&self, route_id_blob: Vec<u8>) -> Result<()> {
        let routing_context = &self.get_routing_context();
        let dht_record = self.get_dht_record();
        routing_context
            .set_dht_value(
                dht_record.key().clone(),
                ROUTE_ID_DHT_KEY,
                route_id_blob,
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {}", e))?;

        Ok(())
    }

    async fn get_route_id_from_dht(&self, subkey: u32) -> Result<Vec<u8>> {
        let routing_context = &self.get_routing_context();

        // Use the existing DHT record
        let dht_record = self.get_dht_record();

        // Get the stored route ID blob at subkey
        let stored_blob = routing_context
            .get_dht_value(dht_record.key().clone(), ROUTE_ID_DHT_KEY, false)
            .await?
            .ok_or_else(|| anyhow!("Route ID blob not found in DHT"))?;

        Ok(stored_blob.data().to_vec())
    }

    // Send an AppMessage to the repo owner using the stored route ID blob
    async fn send_message_to_owner(
        &self,
        veilid: &VeilidAPI,
        message: Vec<u8>,
        subkey: u32,
    ) -> Result<()> {
        let routing_context = self.get_routing_context();

        // Retrieve the route ID blob from DHT
        let route_id_blob = self.get_route_id_from_dht(subkey).await?;

        // Import the route using the blob via VeilidAPI
        let route_id = match veilid.import_remote_private_route(route_id_blob) {
            Ok(route) => route,
            Err(e) => {
                eprintln!("Failed to import remote private route: {:?}", e);
                return Err(e.into());
            }
        };

        // Send an AppMessage to the repo owner using the imported route ID
        if let Err(e) = routing_context
            .app_message(veilid_core::Target::PrivateRoute(route_id), message)
            .await
        {
            eprintln!("Failed to send message: {:?}", e);
            return Err(e.into());
        }

        Ok(())
    }

    fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }

    async fn members(&self) -> Result<Vec<CryptoKey>> {
        unimplemented!("WIP")
    }

    async fn join(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    async fn leave(&self) -> Result<()> {
        unimplemented!("WIP")
    }
}
