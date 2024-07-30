use async_stream::stream;
use futures_core::stream::Stream;
use serde::{Serialize, Deserialize};
use eyre::{Result, anyhow};
use std::sync::Arc;
use veilid_core::{
    CryptoKey, DHTRecordDescriptor, CryptoTyped, CryptoSystemVLD0, RoutingContext, SharedSecret

#[derive(Clone)]
pub struct Group {
    pub id: CryptoKey,
    pub dht_record: DHTRecordDescriptor,
    pub encryption_key: SharedSecret,
    pub secret_key: Option<CryptoTyped<CryptoKey>>,
    pub routing_context: Arc<RoutingContext>,
    pub crypto_system: CryptoSystemVLD0,
}

impl Group {
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

    pub fn get_id(&self) -> CryptoKey {
        self.id.clone()
    }

    pub fn get_write_key(&self) -> Option<CryptoKey> {
        unimplemented!("WIP")
    }

    pub fn get_encryption_key(&self) -> CryptoKey {
        self.encryption_key.value
    }

    pub async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = &self.routing_context;
        let key = self.dht_record.key().clone();
        let encrypted_name = self.encrypt_aead(name.as_bytes(), None)?;
        routing_context.set_dht_value(key, 0, encrypted_name, None).await?;
        Ok(())
    }

    pub async fn get_name(&self) -> Result<String> {
        let routing_context = &self.routing_context;
        let key = self.dht_record.key().clone();
        let value = routing_context.get_dht_value(key, 0, false).await?;
        match value {
            Some(value) => {
                let decrypted_name = self.decrypt_aead(value.data(), None)?;
                Ok(String::from_utf8(decrypted_name).map_err(|e| anyhow!("Failed to convert DHT value to string: {}", e))?)
            }
            None => Err(anyhow!("Value not found")),
        }
    }

    pub async fn name(&self) -> Result<String> {
        self.get_name().await
    }

    pub async fn members(&self) -> Result<Vec<CryptoKey>> {
        unimplemented!("WIP")
    }

    pub async fn join(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    pub async fn leave(&self) -> Result<()> {
        unimplemented!("WIP")
    }

    pub async fn close(&self) -> Result<()> {
        let routing_context = &self.routing_context;
        let key = self.dht_record.key().clone();
        routing_context.close_dht_record(key).await?;
        Ok(())
    }

    pub fn encrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = self.crypto_system.random_nonce();
        let mut buffer = Vec::with_capacity(nonce.as_slice().len() + data.len());
        buffer.extend_from_slice(nonce.as_slice());
        buffer.extend_from_slice(
            &self
                .crypto_system
                .encrypt_aead(data, &nonce, &self.encryption_key.value, associated_data)
                .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?,
        );
        Ok(buffer)
    }

    pub fn decrypt_aead(&self, data: &[u8], associated_data: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce: [u8; 24] = data[..24].try_into().map_err(|_| anyhow!("Failed to convert nonce slice to array"))?;
        let nonce = Nonce::new(nonce);
        let encrypted_data = &data[24..];
        self.crypto_system
            .decrypt_aead(encrypted_data, &nonce, &self.encryption_key.value, associated_data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))
    }

    pub async fn store_keypair(&self, protected_store: &ProtectedStore) -> Result<()> {
        let keypair = GroupKeypair {
            public_key: self.id.clone(),
            secret_key: self.secret_key.as_ref().map(|sk| sk.value.clone()),
            encryption_key: self.encryption_key.value.clone(),
        };
        let keypair_data = serde_cbor::to_vec(&keypair).map_err(|e| anyhow!("Failed to serialize keypair: {}", e))?;
        protected_store.save_user_secret(self.id.to_string(), &keypair_data).await.map_err(|e| anyhow!("Unable to store keypair: {}", e))?;
        Ok(())
    }
}
