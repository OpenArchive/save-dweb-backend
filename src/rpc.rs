use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use crate::group::Group;
use crate::repo::Repo;
use crate::{
    constants::ROUTE_ID_DHT_KEY,
    group::{PROTOCOL_SCHEME, URL_DHT_KEY, URL_ENCRYPTION_KEY},
};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures::StreamExt;
use hex::ToHex;
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::convert::TryInto;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info};
use url::Url;
use veilid_core::{
    vld0_generate_keypair, CryptoKey, CryptoSystemVLD0, CryptoSystem, DHTRecordDescriptor, DHTSchema,
    RoutingContext, SharedSecret, VeilidAPI, VeilidAppCall, VeilidUpdate, CRYPTO_KIND_VLD0,
};

const MESSAGE_TYPE_REPLICATE_GROUP: u8 = 0x00;
const MESSAGE_TYPE_LIST_GROUPS: u8 = 0x01;
const MESSAGE_TYPE_REMOVE_GROUP: u8 = 0x02;
const MESSAGE_TYPE_ERROR: u8 = 0xFF;

#[repr(u8)]
#[derive(Serialize, Deserialize)]
enum MessageType {
    ReplicateGroup = MESSAGE_TYPE_REPLICATE_GROUP,
    ListGroups = MESSAGE_TYPE_LIST_GROUPS,
    RemoveGroup = MESSAGE_TYPE_REMOVE_GROUP,
}

#[derive(Serialize, Deserialize)]
struct ReplicateGroupRequest {
    group_id: String,
}

#[derive(Serialize, Deserialize)]
struct ReplicateGroupResponse {
    status_message: String,
}

#[derive(Serialize, Deserialize)]
struct ListGroupsResponse {
    group_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RemoveGroupRequest {
    group_id: String,
}

#[derive(Serialize, Deserialize)]
struct RemoveGroupResponse {
    status_message: String,
}

#[derive(Clone)]
pub struct RpcService {
    backend: Backend,
    descriptor: RpcServiceDescriptor,
}

// Just used for app calls
pub struct RpcClient {
    veilid: VeilidAPI,
    routing_context: RoutingContext,
    descriptor: RpcServiceDescriptor,
}

#[derive(Clone)]
pub struct RpcServiceDescriptor {
    keypair: CommonKeypair,
    routing_context: RoutingContext,
    crypto_system: CryptoSystemVLD0,
    dht_record: DHTRecordDescriptor,
}

impl RpcServiceDescriptor {
    pub async fn from_url(url: &str) -> Result<Self> {
        Err(anyhow!("Not implemented"))
    }

    pub fn get_url(&self) -> String {
        let mut url = Url::parse(format!("{0}:?", PROTOCOL_SCHEME).as_str()).unwrap();

        url.query_pairs_mut()
            .append_pair(URL_DHT_KEY, self.get_id().encode_hex::<String>().as_str())
            .append_pair(
                URL_ENCRYPTION_KEY,
                self.get_encryption_key().encode_hex::<String>().as_str(),
            )
            .append_key_only("rpc");
        url.to_string()
    }
}

impl RpcService {
    pub async fn from_backend(backend: &Backend) -> Result<Self> {
        let backend = backend.clone();
        let veilid = backend
            .get_veilid_api()
            .await
            .ok_or_else(|| anyhow!("Backend not started"))?;

        let routing_context = veilid.routing_context()?;
        let schema = DHTSchema::dflt(65)?; // 64 members + a title
        let kind = Some(CRYPTO_KIND_VLD0);

        // TODO: try loading from protected store before creating
        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let owner_keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let encryption_key = crypto_system.random_shared_secret();

        let keypair = CommonKeypair {
            id: dht_record.key().value.clone(),
            public_key: dht_record.owner().clone(),
            secret_key: dht_record.owner_secret().cloned(),
            encryption_key,
        };

        let descriptor = RpcServiceDescriptor {
            keypair,
            routing_context,
            crypto_system,
            dht_record,
        };

        Ok(RpcService {
            backend,
            descriptor,
        })
    }

    // Start listening for AppCall events.
    pub async fn start_update_listener(&self) -> Result<()> {
        // Subscribe to updates from the backend
        let mut update_rx = self
            .backend
            .subscribe_updates()
            .await
            .ok_or_else(|| anyhow!("Failed to subscribe to updates"))?;

        // Listen for incoming updates and handle AppCall
        loop {
            match update_rx.recv().await {
                Ok(update) => {
                    if let VeilidUpdate::AppCall(app_call) = update {
                        let app_call_clone = app_call.clone();

                        if let Err(e) = self.handle_app_call(*app_call).await {
                            error!("Error processing AppCall: {}", e);
            
                            // Send an error response to the AppCall
                            if let Err(err) = self
                                .send_response(app_call_clone.id().into(), MESSAGE_TYPE_ERROR, &e.to_string())
                                .await
                            {
                                error!("Failed to send error response: {}", err);
                            }
                        }
                    }
                }
                Err(RecvError::Lagged(count)) => {
                    error!("Missed {} updates", count);
                }
                Err(RecvError::Closed) => {
                    error!("Update channel closed");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_app_call(&self, app_call: VeilidAppCall) -> Result<()> {
        let call_id = app_call.id();
        let message = app_call.message();

        if message.is_empty() {
            return Err(anyhow!("Empty message"));
        }

        let message_type_byte = message[0];
        let payload = &message[1..];

        match message_type_byte {
            MESSAGE_TYPE_REPLICATE_GROUP => {
                let request: ReplicateGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.replicate_group(request).await?;
                self.send_response(call_id.into(), MESSAGE_TYPE_REPLICATE_GROUP, &response).await?;
            }
            MESSAGE_TYPE_LIST_GROUPS => {
                let response = self.list_groups().await?;
                self.send_response(call_id.into(), MESSAGE_TYPE_LIST_GROUPS, &response).await?;
            }
            MESSAGE_TYPE_REMOVE_GROUP => {
                let request: RemoveGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.remove_group(request).await?;
                self.send_response(call_id.into(), MESSAGE_TYPE_REMOVE_GROUP, &response).await?;
            }
            _ => {
                error!("Unknown message type: {}", message_type_byte);
                self.send_response(call_id.into(), MESSAGE_TYPE_ERROR, b"Unknown message type").await?;
            }
        }

        Ok(())
    }

    async fn send_response<T: Serialize>(
        &self,
        call_id: u64,
        message_type: u8,
        response: &T,
    ) -> Result<()> {
        let mut response_buf = vec![message_type];
        let payload = serde_cbor::to_vec(response)?;
        response_buf.extend_from_slice(&payload);

        self.backend
            .get_veilid_api()
            .await
            .ok_or_else(|| anyhow!("Veilid API not available"))?
            .app_call_reply(call_id.into(), response_buf)
            .await?;

        Ok(())
    }

    async fn replicate_group(
        &self,
        request: ReplicateGroupRequest,
    ) -> Result<ReplicateGroupResponse> {
        let group_id = request.group_id;
        info!("Replicating group with ID: {}", group_id);

        let group_bytes = URL_SAFE_NO_PAD.decode(&group_id)?;
        let group_bytes: [u8; 32] = group_bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("Expected 32 bytes, got {}", v.len()))?;
        let group_key = CryptoKey::new(group_bytes);

        let backend = self.backend.clone();
        let group = backend.get_group(&group_key).await?;

        let repo_keys: Vec<CryptoKey> = group.list_repos().await;

        for repo_key in repo_keys {
            info!("Processing repository with crypto key: {:?}", repo_key);

            let repo = group.get_repo(&repo_key).await?;
            replicate_repo(&group, &repo).await?;
        }

        Ok(ReplicateGroupResponse {
            status_message: format!("Successfully replicated group: {}", group_id),
        })
    }


    async fn list_groups(&self) -> Result<ListGroupsResponse> {
        let backend = self.backend.clone();
        let groups = backend.list_groups().await?;

        let group_ids: Vec<String> = groups.iter().map(|g| g.id().to_string()).collect();

        Ok(ListGroupsResponse { group_ids })
    }

    async fn remove_group(&self, request: RemoveGroupRequest) -> Result<RemoveGroupResponse> {
        let group_id = request.group_id;
        info!("Removing group with ID: {}", group_id);

        let group_bytes = URL_SAFE_NO_PAD.decode(&group_id)?;
        let group_bytes: [u8; 32] = group_bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("Expected 32 bytes, got {}", v.len()))?;
        let group_key = CryptoKey::new(group_bytes);

        let backend = self.backend.clone();
        backend.close_group(group_key).await?;

        Ok(RemoveGroupResponse {
            status_message: format!("Successfully removed group: {}", group_id),
        })
    }
}

async fn replicate_repo(group: &Group, repo: &Repo) -> Result<()> {
    if !repo.can_write() {
        let collection_hash = repo.get_hash_from_dht().await?;
        if !group.has_hash(&collection_hash).await? {
            download(group, &collection_hash).await?;
        }
    }

    // List the files in the repo
    let files = repo.list_files().await?;

    for file_name in files {
        info!("Processing file: {}", file_name);

        let file_hash = repo.get_file_hash(&file_name).await?;

        // If the repo is not writable and the file hash is not found in the group, attempt to download it.
        if !repo.can_write() && !group.has_hash(&file_hash).await? {
            download(group, &file_hash).await?;
        }
        // Attempt to retrieve the file using download_file_from
        if let Ok(route_id_blob) = repo.get_route_id_blob().await {
            group
                .iroh_blobs
                .download_file_from(route_id_blob, &file_hash)
                .await?;
            info!("Successfully replicated file: {}", file_name);
        } else {
            error!("Failed to get route ID blob for file: {}", file_name);
        }
    }

    Ok(())
}

async fn download(group: &Group, hash: &Hash) -> Result<()> {
    let repo_keys: Vec<CryptoKey> = group.list_repos().await;

    if repo_keys.is_empty() {
        return Err(anyhow!("Cannot download hash. No repos found"));
    }

    for repo_key in repo_keys.iter() {
        let repo = group.get_repo(repo_key).await?;
        if let Ok(route_id_blob) = repo.get_route_id_blob().await {
            println!(
                "Downloading {} from {} via {:?}",
                hash,
                repo.id(),
                route_id_blob
            );
            // Attempt to download the file from the peer
            let result = group
                .iroh_blobs
                .download_file_from(route_id_blob, hash)
                .await;
            if result.is_ok() {
                return Ok(());
            } else {
                eprintln!("Unable to download from peer, {}", result.unwrap_err());
            }
        }
    }

    Err(anyhow!("Unable to download from any peer"))
}

impl DHTEntity for RpcServiceDescriptor {
    async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let encrypted_name = self.encrypt_aead(name.as_bytes(), None)?;
        routing_context
            .set_dht_value(key, 0, encrypted_name, None)
            .await?;
        Ok(())
    }

    fn get_id(&self) -> CryptoKey {
        self.keypair.id.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        self.keypair.secret_key.clone()
    }

    fn get_encryption_key(&self) -> SharedSecret {
        self.keypair.encryption_key.clone()
    }

    fn get_dht_record(&self) -> DHTRecordDescriptor {
        self.dht_record.clone()
    }

    fn get_routing_context(&self) -> RoutingContext {
        self.routing_context.clone()
    }

    fn get_crypto_system(&self) -> CryptoSystemVLD0 {
        self.crypto_system.clone()
    }
}
