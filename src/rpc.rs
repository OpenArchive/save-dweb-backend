use crate::backend::{record_key_from_query, Backend};
use crate::common::{make_route, DHTEntity};
use crate::group::Group;
use crate::repo::Repo;
use crate::{
    constants::ROUTE_ID_DHT_KEY,
    group::{PROTOCOL_SCHEME, URL_DHT_KEY, URL_ENCRYPTION_KEY, URL_PUBLIC_KEY, URL_SECRET_KEY},
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
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use url::Url;
use veilid_core::{
    CryptoSystem, DHTRecordDescriptor, DHTSchema, KeyPair, PublicKey, RecordKey, RouteId,
    RoutingContext, SecretKey, SetDHTValueOptions, SharedSecret, Target, VeilidAPI, VeilidAppCall,
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
    // RPC has its own private route, distinct from the tunnel's route used by
    // veilid-iroh-blobs. Both subscribe to the same VeilidUpdate broadcast, so
    // we filter incoming AppCalls by route_id to avoid racing the tunnel
    // listener (which since v0.3.4 actively replies InvalidFormat to anything
    // it can't parse as a tunnel frame).
    //
    // Wrapped in Arc<RwLock<_>> because the route can be rebuilt at runtime
    // when veilid notifies us via VeilidUpdate::RouteChange that ours died.
    route_id: Arc<RwLock<RouteId>>,
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

    let dht_key = record_key_from_query(&url, URL_DHT_KEY)
        .map_err(|_| anyhow!("Missing 'dht' key in the URL"))?;
    let encryption_key = crate::backend::shared_secret_from_query(&url, URL_ENCRYPTION_KEY)
        .map_err(|_| anyhow!("Missing 'enc' key in the URL"))?;
    let owner_public_key = crate::backend::public_key_from_query(&url, URL_PUBLIC_KEY)
        .map_err(|_| anyhow!("Missing 'pk' key in the URL"))?;
    let owner_secret_key = Some(
        crate::backend::secret_key_from_query(&url, URL_SECRET_KEY)
            .map_err(|_| anyhow!("Missing 'sk' key in the URL"))?,
    );

    Ok(RpcKeys {
        dht_key,
        encryption_key,
        owner_public_key,
        owner_secret_key,
    })
}

impl RpcClient {
    pub async fn from_veilid(veilid: VeilidAPI, url: &str) -> Result<Self> {
        let routing_context = veilid.routing_context()?;
        let crypto_system = veilid
            .crypto()?
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"));

        let descriptor =
            RpcServiceDescriptor::from_url(routing_context.clone(), veilid.clone(), url).await?;

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
        let message = serde_cbor::to_vec(request)?;

        let blob = self.descriptor.get_route_id_blob().await?;
        let route_id = self.veilid.import_remote_private_route(blob)?;
        let target = Target::RouteId(route_id);

        let mut payload = vec![message_type];
        payload.extend_from_slice(&message);

        let response = self.routing_context.app_call(target, payload).await?;

        if response.is_empty() {
            return Err(anyhow!("Empty response received from RPC call"));
        }

        let response_message_type = response[0];
        let payload = &response[1..];

        if response_message_type == MESSAGE_TYPE_ERROR {
            let rpc_response: RpcResponse<()> = serde_cbor::from_slice(payload)?;
            if let Some(err) = rpc_response.error {
                return Err(anyhow!("RPC Error: {err}"));
            } else {
                return Err(anyhow!("Unknown error format in RPC response"));
            }
        }

        if response_message_type != message_type {
            return Err(anyhow!(
                "Unexpected message type in response. Expected: {message_type}, Got: {response_message_type}"
            ));
        }

        let rpc_response: RpcResponse<R> = serde_cbor::from_slice(payload)?;

        if let Some(data) = rpc_response.success {
            return Ok(data);
        }

        Err(anyhow!(
            "RPC Response is missing both success and error fields"
        ))
    }

    pub async fn get_name(&self) -> Result<String> {
        self.descriptor.get_name().await
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
    pub dht_key: RecordKey,
    pub encryption_key: SharedSecret,
    pub owner_public_key: PublicKey,
    pub owner_secret_key: Option<SecretKey>,
}

#[derive(Clone)]
pub struct RpcServiceDescriptor {
    keypair: RpcKeys,
    routing_context: RoutingContext,
    veilid: VeilidAPI,
    dht_record: DHTRecordDescriptor,
}

impl RpcServiceDescriptor {
    pub async fn from_url(
        routing_context: RoutingContext,
        veilid: VeilidAPI,
        url: &str,
    ) -> Result<Self> {
        let keys = parse_url_for_rpc(url)?;

        let record_key = keys.dht_key.clone();

        // In v0.5.1, DHT encryption is enabled by default, so we need to provide the owner keypair
        // to decrypt. We get this from the URL that was shared with us.
        let bare_keypair = veilid_core::BareKeyPair::new(
            keys.owner_public_key.clone().into_value(),
            keys.owner_secret_key.clone().unwrap().into_value(),
        );
        let dht_record = routing_context
            .open_dht_record(
                record_key,
                Some(KeyPair::new(CRYPTO_KIND_VLD0, bare_keypair)),
            )
            .await
            .map_err(|e| anyhow!("Failed to open DHT record: {e}"))?;

        Ok(RpcServiceDescriptor {
            keypair: keys,
            routing_context,
            veilid,
            dht_record,
        })
    }

    pub fn get_url(&self) -> Result<String> {
        let owner_secret = self
            .dht_record
            .owner_secret()
            .ok_or_else(|| anyhow!("Cannot generate URL: no owner secret"))?;
        let mut url = Url::parse(format!("{PROTOCOL_SCHEME}:?").as_str()).unwrap();

        url.query_pairs_mut()
            .append_pair(URL_DHT_KEY, self.get_id().ref_value().encode().as_str())
            .append_pair(
                URL_ENCRYPTION_KEY,
                hex::encode(self.get_encryption_key().ref_value().bytes()).as_str(),
            )
            .append_pair(
                URL_PUBLIC_KEY,
                hex::encode(self.dht_record.owner().ref_value().bytes()).as_str(),
            )
            .append_pair(
                URL_SECRET_KEY,
                hex::encode(owner_secret.ref_value().bytes()).as_str(),
            )
            .append_key_only("rpc");

        let url_string = url.to_string();
        info!("Descriptor URL generated (redacted)");
        Ok(url_string)
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
        self.routing_context
            .set_dht_value(
                self.dht_record.key().clone(),
                ROUTE_SUBKEY,
                route_id_blob,
                Some(SetDHTValueOptions::default()),
            )
            .await
            .map_err(|e| anyhow!("Failed to store route ID blob in DHT: {e}"))?;

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

        // TODO: try loading from protected store before creating
        let dht_record = routing_context
            .create_dht_record(CRYPTO_KIND_VLD0, schema, None)
            .await?;
        let crypto = veilid.crypto()?;
        let crypto_system = crypto
            .get(CRYPTO_KIND_VLD0)
            .ok_or_else(|| anyhow!("Unable to init crypto system"))?;

        let encryption_key = crypto_system.random_shared_secret();

        let keypair = RpcKeys {
            dht_key: dht_record.key().clone(),
            encryption_key,
            owner_public_key: dht_record.owner().clone(),
            owner_secret_key: dht_record.owner_secret().clone(),
        };

        let descriptor = RpcServiceDescriptor {
            keypair,
            routing_context,
            veilid: veilid.clone(),
            dht_record,
        };

        // Allocate a private route dedicated to RPC traffic. This MUST NOT be
        // the same route the tunnel manager owns; otherwise both update
        // listeners would race to call app_call_reply for every incoming
        // AppCall and the tunnel's InvalidFormat reply would clobber ours.
        let (route_id, route_id_blob) = make_route(&veilid).await?;
        descriptor.update_route_on_dht(route_id_blob).await?;

        Ok(RpcService {
            backend,
            descriptor,
            route_id: Arc::new(RwLock::new(route_id)),
        })
    }

    /// Rebuild our private route after veilid reports it dead, and re-publish
    /// the new blob to our DHT subkey so clients can pick it up on their next
    /// fetch.
    async fn rebuild_route(&self) -> Result<()> {
        let veilid = self
            .backend
            .get_veilid_api()
            .await
            .ok_or_else(|| anyhow!("Veilid API not available"))?;

        let (new_route_id, new_route_blob) = make_route(&veilid).await?;
        self.descriptor.update_route_on_dht(new_route_blob).await?;
        *self.route_id.write().await = new_route_id;
        info!("RPC private route rebuilt and re-published to DHT");
        Ok(())
    }

    pub fn get_descriptor_url(&self) -> Result<String> {
        self.descriptor.get_url()
    }

    // Start listening for AppCall events.
    pub async fn start_update_listener(&self) -> Result<()> {
        let mut update_rx = self
            .backend
            .subscribe_updates()
            .await
            .ok_or_else(|| anyhow!("Failed to subscribe to updates"))?;

        loop {
            match update_rx.recv().await {
                Ok(VeilidUpdate::AppCall(app_call)) => {
                    let app_call_clone = app_call.clone();

                    if let Err(e) = self.handle_app_call(*app_call).await {
                        error!("Error processing AppCall: {}", e);

                        // Only reply with an error if the call was actually
                        // for our route; otherwise we'd be replying to
                        // tunnel calls and racing the tunnel listener.
                        if self.is_for_us(&app_call_clone).await {
                            let error_response: RpcResponse<()> = RpcResponse {
                                success: None,
                                error: Some(e.to_string()),
                            };
                            let call_id: u64 = app_call_clone.id().into();
                            if let Err(err) = self
                                .send_response(call_id, MESSAGE_TYPE_ERROR, &error_response)
                                .await
                            {
                                error!("Failed to send error response: {}", err);
                            }
                        }
                    }
                }
                Ok(VeilidUpdate::RouteChange(rc)) => {
                    let our_route = self.route_id.read().await.clone();
                    if rc.dead_routes.contains(&our_route) {
                        warn!("RPC private route {:?} died; rebuilding", our_route);
                        if let Err(err) = self.rebuild_route().await {
                            error!("Failed to rebuild RPC private route: {err}");
                        }
                    }
                }
                Ok(_) => {}
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

    /// Returns true iff the AppCall arrived on this RPC service's current
    /// private route. AppCalls for the tunnel's route (or with no route at
    /// all) belong to veilid-iroh-blobs and we must ignore them.
    async fn is_for_us(&self, app_call: &VeilidAppCall) -> bool {
        match app_call.route_id() {
            Some(rid) => rid == &*self.route_id.read().await,
            None => false,
        }
    }

    async fn handle_app_call(&self, app_call: VeilidAppCall) -> Result<()> {
        if !self.is_for_us(&app_call).await {
            debug!(
                "Ignoring AppCall on foreign route_id={:?}",
                app_call.route_id()
            );
            return Ok(());
        }

        let call_id: u64 = app_call.id().into();
        let message = app_call.message();

        if message.is_empty() {
            let error_response: RpcResponse<()> = RpcResponse {
                success: None,
                error: Some("Empty message".to_string()),
            };
            self.send_response(call_id, MESSAGE_TYPE_ERROR, &error_response)
                .await?;
            return Err(anyhow!("Empty message"));
        }

        let message_type_byte = message[0];
        let payload = &message[1..];

        info!("Handling RPC call: type={}", message_type_byte);

        match message_type_byte {
            MESSAGE_TYPE_JOIN_GROUP => {
                let request: JoinGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.join_group(request).await;
                self.send_response(call_id, MESSAGE_TYPE_JOIN_GROUP, &response)
                    .await?;
            }
            MESSAGE_TYPE_LIST_GROUPS => {
                let response = self.list_groups().await;
                self.send_response(call_id, MESSAGE_TYPE_LIST_GROUPS, &response)
                    .await?;
            }
            MESSAGE_TYPE_REMOVE_GROUP => {
                let request: RemoveGroupRequest = serde_cbor::from_slice(payload)?;
                let response = self.remove_group(request).await;
                self.send_response(call_id, MESSAGE_TYPE_REMOVE_GROUP, &response)
                    .await?;
            }
            _ => {
                error!("Unknown message type: {}", message_type_byte);
                let error_response: RpcResponse<()> = RpcResponse {
                    success: None,
                    error: Some("Unknown message type".to_string()),
                };
                self.send_response(call_id, MESSAGE_TYPE_ERROR, &error_response)
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
        info!(
            "Sending RPC response: type={}, payload_len={}",
            message_type,
            payload.len()
        );
        response_buf.extend_from_slice(&payload);

        self.backend
            .get_veilid_api()
            .await
            .ok_or_else(|| anyhow!("Veilid API not available"))?
            .app_call_reply(call_id.into(), response_buf)
            .await?;

        Ok(())
    }

    pub async fn set_name(&self, name: &str) -> Result<()> {
        self.descriptor.set_name(name).await
    }
    pub async fn get_name(&self) -> Result<String> {
        self.descriptor.get_name().await
    }

    pub async fn join_group(&self, request: JoinGroupRequest) -> RpcResponse<JoinGroupResponse> {
        let group_url = request.group_url;
        info!("Joining group with URL (redacted)");

        let backend = self.backend.clone();

        match backend.join_from_url(&group_url).await {
            Ok(group) => {
                let repo_keys: Vec<RecordKey> = group.list_repos().await;

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
                            "Successfully joined and replicated group from URL: {group_url}"
                        ),
                    }),
                    error: None,
                }
            }
            Err(err) => RpcResponse {
                success: None,
                error: Some(format!("Failed to join group: {err}")),
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
                error: Some(format!("Failed to list groups: {err}")),
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
                    error: Some(format!("Failed to decode group ID: {err}")),
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

        let group_key = RecordKey::new(
            CRYPTO_KIND_VLD0,
            veilid_core::BareRecordKey::new(
                veilid_core::BareOpaqueRecordKey::from(&group_bytes[..]),
                None,
            ),
        );

        match backend.close_group(group_key).await {
            Ok(_) => RpcResponse {
                success: Some(RemoveGroupResponse {
                    status_message: format!("Successfully removed group: {group_id}"),
                }),
                error: None,
            },
            Err(err) => RpcResponse {
                success: None,
                error: Some(format!("Failed to remove group: {err}")),
            },
        }
    }

    pub async fn replicate_known_groups(&self) -> Result<()> {
        info!("Replicating all known groups...");

        let group_ids = self.backend.list_known_group_ids().await?;

        for group_id in group_ids {
            info!("Replicating group with ID: {:?}", group_id);

            let group = self.backend.get_group(&group_id).await?;

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

    let files = repo.list_files().await?;

    for file_name in files {
        info!("Processing file: {}", file_name);

        let file_hash = repo.get_file_hash(&file_name).await?;

        if !repo.can_write() && !group.has_hash(&file_hash).await? {
            download(group, &file_hash).await?;
        }
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
    group.download_hash_from_peers(hash).await
}

impl DHTEntity for RpcServiceDescriptor {
    async fn set_name(&self, name: &str) -> Result<()> {
        let routing_context = self.get_routing_context();
        let key = self.get_dht_record().key().clone();
        let encrypted_name = self.encrypt_aead(name.as_bytes(), None)?;
        routing_context
            .set_dht_value(key, 0, encrypted_name, Some(SetDHTValueOptions::default()))
            .await?;
        Ok(())
    }

    fn get_id(&self) -> RecordKey {
        self.dht_record.key().clone()
    }

    fn get_secret_key(&self) -> Option<SecretKey> {
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

    fn get_veilid_api(&self) -> VeilidAPI {
        self.veilid.clone()
    }
}
