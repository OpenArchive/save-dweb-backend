use crate::backend::{crypto_key_from_query, Backend};
use crate::common::DHTEntity;
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
use std::sync::Arc;
use std::vec;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info};
use url::Url;
use veilid_core::{
    vld0_generate_keypair, CryptoKey, CryptoSystem, CryptoSystemVLD0, DHTRecordDescriptor,
    DHTSchema, KeyPair, RoutingContext, SharedSecret, Target, TypedKey, VeilidAPI, VeilidAppCall,
    VeilidUpdate, CRYPTO_KIND_VLD0,
};
use veilid_iroh_blobs::tunnels::OnNewRouteCallback;

const MESSAGE_TYPE_JOIN_GROUP: u8 = 0x00;
const MESSAGE_TYPE_LIST_GROUPS: u8 = 0x01;
const MESSAGE_TYPE_REMOVE_GROUP: u8 = 0x02;
const MESSAGE_TYPE_ERROR: u8 = 0xFF;

const ROUTE_SUBKEY: u32 = 1;

#[repr(u8)]
#[derive(Serialize, Deserialize)]
enum MessageType {
    JoinGroup = MESSAGE_TYPE_JOIN_GROUP,
    ListGroups = MESSAGE_TYPE_LIST_GROUPS,
    RemoveGroup = MESSAGE_TYPE_REMOVE_GROUP,
}

#[derive(Serialize, Deserialize)]
pub struct JoinGroupRequest {
    pub group_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct JoinGroupResponse {
    status_message: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListGroupsRequest;

#[derive(Serialize, Deserialize)]
pub struct ListGroupsResponse {
    pub group_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveGroupRequest {
    pub group_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveGroupResponse {
    status_message: String,
}

#[derive(Clone)]
pub struct RpcService {
    backend: Backend,
    descriptor: RpcServiceDescriptor,
}

#[derive(Serialize, Deserialize)]
pub struct RpcResponse<T> {
    pub success: Option<T>,
    pub error: Option<String>,
}

// Just used for app calls
pub struct RpcClient {
    veilid: VeilidAPI,
    routing_context: RoutingContext,
    descriptor: RpcServiceDescriptor,
}

pub fn parse_url_for_rpc(url_string: &str) -> Result<RpcKeys> {
    let url = Url::parse(url_string)?;

    let dht_key = crypto_key_from_query(&url, URL_DHT_KEY)
        .map_err(|_| anyhow!("Missing 'dht' key in the URL"))?;
    let encryption_key = crypto_key_from_query(&url, URL_ENCRYPTION_KEY)
        .map_err(|_| anyhow!("Missing 'enc' key in the URL"))?;

    Ok(RpcKeys {
        dht_key,
        encryption_key,
    })
}

impl RpcClient {
    pub async fn from_veilid(veilid: VeilidAPI, url: &str) -> Result<Self> {
        let routing_context = veilid.routing_context()?;
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let descriptor =
            RpcServiceDescriptor::from_url(routing_context.clone(), crypto_system, url).await?;

        Ok(RpcClient {
            veilid,
            routing_context,
            descriptor,
        })
    }

    async fn send_rpc_request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        request: &T,
        message_type: u8,
    ) -> Result<R> {
        // Serialize the request
        let message = serde_cbor::to_vec(request)?;

        // Get the route ID blob and target
        let blob = self.descriptor.get_route_id_blob().await?;
        let route_id = self.veilid.import_remote_private_route(blob)?;
        let target = Target::PrivateRoute(route_id);

        // Prefix the message type byte
        let mut payload = vec![message_type];
        payload.extend_from_slice(&message);

        // Send the app call and wait for the response
        let response = self.routing_context.app_call(target, payload).await?;

        // Parse the response
        let response: RpcResponse<R> = serde_cbor::from_slice(&response)?;

        // Handle success or error
        match response {
            RpcResponse {
                success: Some(data),
                error: None,
            } => Ok(data),
            RpcResponse {
                success: None,
                error: Some(err),
            } => Err(anyhow!("RPC Error: {}", err)),
            _ => Err(anyhow!("Unexpected response format")),
        }
    }

    pub async fn join_group(&self, group_url: String) -> Result<JoinGroupResponse> {
        let request = JoinGroupRequest { group_url };
        self.send_rpc_request(&request, MESSAGE_TYPE_JOIN_GROUP)
            .await
    }

    pub async fn list_groups(&self) -> Result<ListGroupsResponse> {
        let request = ListGroupsRequest;
        self.send_rpc_request(&request, MESSAGE_TYPE_LIST_GROUPS)
            .await
    }

    pub async fn remove_group(&self, group_id: String) -> Result<RemoveGroupResponse> {
        let request = RemoveGroupRequest { group_id };
        self.send_rpc_request(&request, MESSAGE_TYPE_REMOVE_GROUP)
            .await
    }
}

#[derive(Clone)]
pub struct RpcKeys {
    pub dht_key: CryptoKey,
    pub encryption_key: SharedSecret,
}

#[derive(Clone)]
pub struct RpcServiceDescriptor {
    keypair: RpcKeys,
    routing_context: RoutingContext,
    crypto_system: CryptoSystemVLD0,
    dht_record: DHTRecordDescriptor,
}

impl RpcServiceDescriptor {
    pub async fn from_url(
        routing_context: RoutingContext,
        crypto_system: CryptoSystemVLD0,
        url: &str,
    ) -> Result<Self> {
        let keys = parse_url_for_rpc(url)?;

        let record_key = TypedKey::new(CRYPTO_KIND_VLD0, keys.dht_key);

        let dht_record = routing_context
            .open_dht_record(record_key.clone(), None)
            .await
            .map_err(|e| anyhow!("Failed to open DHT record: {}", e))?;

        let owner_key = dht_record.owner();

        Ok(RpcServiceDescriptor {
            keypair: keys,
            routing_context,
            crypto_system,
            dht_record,
        })
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

        let url_string = url.to_string();
        info!("Descriptor URL: {}", url_string);
        url_string
    }
    pub async fn get_route_id_blob(&self) -> Result<Vec<u8>> {
        let value = self
            .routing_context
            .get_dht_value(self.dht_record.key().clone(), ROUTE_SUBKEY, true)
            .await?
            .ok_or_else(|| anyhow!("Unable to get DHT value for route id blob"))?
            .data()
            .to_vec();
        Ok(value)
    }

    pub async fn update_route_on_dht(&self, route_id_blob: Vec<u8>) -> Result<()> {
        // Set the root hash in the DHT record
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                ROUTE_SUBKEY,
                route_id_blob,
                None,
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {}", e))?;

        Ok(())
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
        let schema = DHTSchema::dflt(2)?; // Title + Route Id
        let kind = Some(CRYPTO_KIND_VLD0);

        // TODO: try loading from protected store before creating
        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let owner_keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let encryption_key = crypto_system.random_shared_secret();

        let keypair = RpcKeys {
            dht_key: dht_record.key().value.clone(),
            encryption_key,
        };

        let descriptor = RpcServiceDescriptor {
            keypair,
            routing_context,
            crypto_system,
            dht_record,
        };

        let updatable_descriptor = descriptor.clone();

        let on_new_route_callback: OnNewRouteCallback = Arc::new(move |route_id, route_id_blob| {
            let updatable_descriptor = updatable_descriptor.clone();

            tokio::spawn(async move {
                if let Err(err) = updatable_descriptor
                    .update_route_on_dht(route_id_blob)
                    .await
                {
                    eprintln!(
                        "Unable to update route after rebuild for RPC service: {}",
                        err
                    );
                }
            });
        });

        let route_id_blob = backend.get_route_id_blob().await?;
        descriptor.update_route_on_dht(route_id_blob).await?;

        Ok(RpcService {
            backend,
            descriptor,
        })
    }

    pub fn get_descriptor_url(&self) -> String {
        self.descriptor.get_url()
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

                            // Wrap the error in RpcResponse and send it
                            let error_response: RpcResponse<()> = RpcResponse {
                                success: None,
                                error: Some(e.to_string()),
                            };
                            if let Err(err) = self
                                .send_response(
                                    app_call_clone.id().into(),
                                    MESSAGE_TYPE_ERROR,
                                    &error_response,
                                )
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
            let error_response: RpcResponse<()> = RpcResponse {
                success: None,
                error: Some("Empty message".to_string()),
            };
            self.send_response(call_id.into(), MESSAGE_TYPE_ERROR, &error_response)
                .await?;
            return Err(anyhow!("Empty message"));
        }

        let message_type_byte = message[0];
        let payload = &message[1..];

        match message_type_byte {
            MESSAGE_TYPE_JOIN_GROUP => {
                let request: JoinGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.join_group(request).await;
                self.send_response(call_id.into(), MESSAGE_TYPE_JOIN_GROUP, &response)
                    .await?;
            }
            MESSAGE_TYPE_LIST_GROUPS => {
                let response = self.list_groups().await;
                self.send_response(call_id.into(), MESSAGE_TYPE_LIST_GROUPS, &response)
                    .await?;
            }
            MESSAGE_TYPE_REMOVE_GROUP => {
                let request: RemoveGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.remove_group(request).await;
                self.send_response(call_id.into(), MESSAGE_TYPE_REMOVE_GROUP, &response)
                    .await?;
            }
            _ => {
                error!("Unknown message type: {}", message_type_byte);
                let error_response: RpcResponse<()> = RpcResponse {
                    success: None,
                    error: Some("Unknown message type".to_string()),
                };
                self.send_response(call_id.into(), MESSAGE_TYPE_ERROR, &error_response)
                    .await?;
            }
        }

        Ok(())
    }

    async fn send_response<T: Serialize>(
        &self,
        call_id: u64,
        message_type: u8,
        response: &RpcResponse<T>,
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

    pub async fn join_group(&self, request: JoinGroupRequest) -> RpcResponse<JoinGroupResponse> {
        let group_url = request.group_url;
        info!("Joining group with URL: {}", group_url);

        // Use the backend to join the group from the provided URL
        let backend = self.backend.clone();

        match backend.join_from_url(&group_url).await {
            Ok(group) => {
                let repo_keys: Vec<CryptoKey> = group.list_repos().await;

                for repo_key in repo_keys {
                    if let Ok(repo) = group.get_repo(&repo_key).await {
                        if let Err(err) = replicate_repo(&group, &repo).await {
                            error!("Failed to replicate repository: {:?}", err);
                        }
                    }
                }

                RpcResponse {
                    success: Some(JoinGroupResponse {
                        status_message: format!(
                            "Successfully joined and replicated group from URL: {}",
                            group_url
                        ),
                    }),
                    error: None,
                }
            }
            Err(err) => RpcResponse {
                success: None,
                error: Some(format!("Failed to join group: {}", err)),
            },
        }
    }

    pub async fn list_groups(&self) -> RpcResponse<ListGroupsResponse> {
        let backend = self.backend.clone();

        match backend.list_groups().await {
            Ok(groups) => RpcResponse {
                success: Some(ListGroupsResponse {
                    group_ids: groups.iter().map(|g| g.id().to_string()).collect(),
                }),
                error: None,
            },
            Err(err) => RpcResponse {
                success: None,
                error: Some(format!("Failed to list groups: {}", err)),
            },
        }
    }

    pub async fn remove_group(
        &self,
        request: RemoveGroupRequest,
    ) -> RpcResponse<RemoveGroupResponse> {
        let group_id = request.group_id;
        info!("Removing group with ID: {}", group_id);

        let backend = self.backend.clone();

        let group_bytes = match URL_SAFE_NO_PAD.decode(&group_id) {
            Ok(bytes) => bytes,
            Err(err) => {
                return RpcResponse {
                    success: None,
                    error: Some(format!("Failed to decode group ID: {}", err)),
                };
            }
        };

        let group_bytes: [u8; 32] = match group_bytes.try_into() {
            Ok(bytes) => bytes,
            Err(v) => {
                return RpcResponse {
                    success: None,
                    error: Some(format!("Expected 32 bytes, got {}", v.len())),
                };
            }
        };

        let group_key = CryptoKey::new(group_bytes);

        match backend.close_group(group_key).await {
            Ok(_) => RpcResponse {
                success: Some(RemoveGroupResponse {
                    status_message: format!("Successfully removed group: {}", group_id),
                }),
                error: None,
            },
            Err(err) => RpcResponse {
                success: None,
                error: Some(format!("Failed to remove group: {}", err)),
            },
        }
    }

    pub async fn replicate_known_groups(&self) -> Result<()> {
        info!("Replicating all known groups...");

        // Fetch all known group IDs from the backend
        let group_ids = self.backend.list_known_group_ids().await?;

        // Iterate over each group and replicate it
        for group_id in group_ids {
            info!("Replicating group with ID: {:?}", group_id);

            // Retrieve the group object
            let group = self.backend.get_group(&group_id).await?;

            // Fetch and replicate all repositories within the group
            for repo_key in group.list_repos().await {
                info!("Processing repository with crypto key: {:?}", repo_key);

                let repo = group.get_repo(&repo_key).await?;
                replicate_repo(&group, &repo).await?;
            }
        }

        info!("All known groups replicated successfully.");
        Ok(())
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
        self.dht_record.key().value.clone()
    }

    fn get_secret_key(&self) -> Option<CryptoKey> {
        None
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
