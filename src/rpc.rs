use crate::backend::Backend;
use crate::common::{CommonKeypair, DHTEntity};
use crate::group::Group;
use crate::repo::Repo;
use crate::{
    constants::ROUTE_ID_DHT_KEY,
    group::{PROTOCOL_SCHEME, URL_DHT_KEY, URL_ENCRYPTION_KEY},
};

use anyhow::anyhow;
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures::StreamExt;
use hex::ToHex;
use iroh::net::discovery::pkarr::dht;
use iroh_blobs::Hash;
use prost::Message;
use std::convert::TryInto;
use std::fs;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::sync::broadcast::error::RecvError;
use tonic::async_trait;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{error, info};
use url::Url;
use veilid_core::{
    vld0_generate_keypair, CryptoKey, CryptoSystem, CryptoSystemVLD0, DHTRecordDescriptor,
    DHTSchema, RoutingContext, SharedSecret, VeilidAPI, VeilidAppCall, VeilidState, VeilidUpdate,
    CRYPTO_KEY_LENGTH, CRYPTO_KIND_VLD0,
};

use tonic_reflection::server::Builder;

tonic::include_proto!("rpc");
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("../descriptor.bin");

#[derive(Clone)]
pub struct RpcService {
    backend: Backend,
    keypair: CommonKeypair,
    routing_context: RoutingContext,
    crypto_system: CryptoSystemVLD0,
    dht_record: DHTRecordDescriptor,
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

        let dht_record = routing_context.create_dht_record(schema, kind).await?;
        let owner_keypair = vld0_generate_keypair();
        let crypto_system = CryptoSystemVLD0::new(veilid.crypto()?);

        let encryption_key = crypto_system.random_shared_secret();

        let keypair = CommonKeypair {
            id: dht_record.key().value.clone(),
            public_key: dht_record.owner().clone(),
            secret_key: dht_record.owner_secret().cloned(),
            encryption_key: encryption_key,
        };

        Ok(RpcService {
            backend,
            keypair,
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
        url.to_string()
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
                    match update {
                        VeilidUpdate::AppCall(app_call) => {
                            // Attempt to parse the app_call message with Protocol Buffers
                            let parsed_call = AppCallRequest::decode(app_call.message());

                            match parsed_call {
                                Ok(request) => {
                                    // Process the parsed AppCall
                                    if let Err(e) = self.process_app_call(request).await {
                                        error!("Error processing AppCall: {}", e);
                                    }
                                }
                                Err(parse_err) => {
                                    // Log the parse error and skip handling this AppCall
                                    error!("Failed to parse AppCall message: {}", parse_err);
                                }
                            }
                        }
                        _ => {
                            // Handle other updates
                            // TO DO: If the hash has changed, download the new file
                        }
                    }
                }
                Err(RecvError::Lagged(count)) => {
                    error!("Missed {} updates", count);
                    // Decide how to handle missed updates
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

        // Attempt to parse the message with Protocol Buffers
        let app_call_request = AppCallRequest::decode(message);
        let response = match app_call_request {
            Ok(request) => {
                info!("Received AppCall with command: {}", request.command);
                self.process_app_call(request).await
            }
            Err(err) => {
                error!("Failed to parse AppCall message: {}", err);
                Ok(AppCallResponse {
                    success: false,
                    message: "Invalid AppCall message format".to_string(),
                })
            }
        };

        // Encode the AppCallResponse
        let mut buf = Vec::new();
        response?.encode(&mut buf).map_err(|e| {
            error!("Failed to encode AppCallResponse: {}", e);
            anyhow!("Failed to encode AppCallResponse: {}", e)
        })?;

        // Send the response using VeilidAPI's app_call_reply
        self.backend
            .get_veilid_api()
            .await
            .ok_or_else(|| anyhow!("Veilid API not available"))?
            .app_call_reply(call_id, buf)
            .await
            .map_err(|e| {
                error!("Failed to send AppCall reply: {}", e);
                anyhow!("Failed to send AppCall reply: {}", e)
            })?;

        Ok(())
    }

    /// Process the AppCallRequest and generate a response
    async fn process_app_call(
        &self,
        request: AppCallRequest,
    ) -> Result<AppCallResponse, anyhow::Error> {
        match request.command.as_str() {
            "ping" => Ok(AppCallResponse {
                success: true,
                message: "pong".to_string(),
            }),
            "echo" => Ok(AppCallResponse {
                success: true,
                message: request.payload,
            }),
            _ => Ok(AppCallResponse {
                success: false,
                message: format!("Unknown command: {}", request.command),
            }),
        }
    }
}

pub async fn start_rpc_server(backend: Backend, addr: &str) -> Result<()> {
    // Path to the keys file
    let base_dir = std::env::current_dir().expect("Failed to get current directory");
    let keys_path = base_dir.join("group_keys.txt");

    // Check if group_keys.txt exists and load keys if it does
    if keys_path.exists() {
        println!("Found existing group_keys.txt, loading group.");

        // Read keys from the file
        let keys_file = File::open(&keys_path)
            .await
            .expect("Failed to open group_keys.txt");
        let mut lines = BufReader::new(keys_file).lines();

        // Extract group_id, secret_key, and encryption_key
        let group_id = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("Missing group ID"))?;
        let secret_key = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("Missing secret key"))?;
        let encryption_key = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow!("Missing encryption key"))?;

        // Transform Key string into CryptoKey
        let bytes = hex::decode(group_id)?;
        let mut key_vec = [0u8; CRYPTO_KEY_LENGTH];
        key_vec.copy_from_slice(&bytes);

        // Convert the byte array to a CryptoKey
        let record_key = CryptoKey::new(key_vec);

        // Use the Backend's `load_group` method to initialize with these keys
        backend.get_group(&record_key).await?;
    } else {
        println!("No group_keys.txt found, loading known groups.");

        // Load known groups from the backend
        backend.load_known_groups().await?;
    };

    // Write keys to file
    // Question: which keys should be loaded here?
    //let base_dir = std::env::current_dir().expect("Failed to get current directory");
    //let keys_path = base_dir.join("group_keys.txt");
    //fs::write(&keys_path, keys).expect("Failed to write group keys to disk");

    //println!("Group keys persisted to {:?}", keys_path);

    let protected_store = backend.get_protected_store().await.unwrap();

    // Create the DHT Record for the RPC service
    let routing_context = backend
        .get_routing_context()
        .await
        .ok_or_else(|| anyhow!("Failed to get routing context"))?;
    let schema = DHTSchema::dflt(65)?; // 64 members + a title
    let kind = Some(CRYPTO_KIND_VLD0);

    let dht_record = routing_context.create_dht_record(schema, kind).await?;
    let keypair = vld0_generate_keypair();

    let veilid_api = backend
        .get_veilid_api()
        .await
        .ok_or_else(|| anyhow!("Failed to get veilid API"))?;
    // Get crypto_system
    let crypto_system = CryptoSystemVLD0::new(veilid_api.crypto().unwrap());

    let encryption_key = crypto_system.random_shared_secret();

    // Initialize keypair
    let keypair = CommonKeypair {
        id: dht_record.key().value.clone(),
        public_key: dht_record.owner().clone(),
        secret_key: Some(keypair.secret.clone()),
        encryption_key: encryption_key.clone(),
    };

    keypair
        .store_keypair(&protected_store)
        .await
        .map_err(|e| anyhow!(e))?;

    let rpc_service = RpcService {
        backend,
        keypair,
        routing_context: routing_context.clone(),
        crypto_system,
        dht_record,
    };

    // Start the update listener
    rpc_service.start_update_listener().await?;

    // Build the reflection service
    let reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;

    Server::builder()
        .add_service(rpc_server::RpcServer::new(rpc_service))
        .add_service(reflection_service)
        .serve(addr.parse()?)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl rpc_server::Rpc for RpcService {
    async fn replicate_group(
        &self,
        request: Request<ReplicateGroupRequest>,
    ) -> Result<Response<ReplicateGroupResponse>, Status> {
        let group_id = request.into_inner().group_id;
        info!("Replicating group with ID: {}", group_id);

        // Decode the Base64URL-encoded group ID into bytes
        let group_bytes = URL_SAFE_NO_PAD.decode(&group_id).map_err(|_| {
            error!("Invalid group ID encoding");
            Status::invalid_argument("Invalid group ID encoding")
        })?;

        // Convert group_bytes to [u8; 32]
        let group_bytes: [u8; 32] = group_bytes.try_into().map_err(|_| {
            error!("Invalid group key length");
            Status::invalid_argument("Invalid group key length")
        })?;

        let group_key = CryptoKey::new(group_bytes);

        let backend = self.backend.clone();
        let group = backend.get_group(&group_key).await.map_err(|e| {
            error!("Failed to get group: {}", e);
            Status::not_found(format!("Group not found: {}", e))
        })?;

        // Use list_repos() to list all repos in the group
        let repo_keys: Vec<CryptoKey> = group.list_repos().await;

        for repo_key in repo_keys {
            info!("Processing repository with crypto key: {:?}", repo_key);

            let repo = group.get_repo(&repo_key).await.map_err(|e| {
                error!("Failed to get repo: {}", e);
                Status::internal(format!("Failed to get repo: {}", e))
            })?;

            // Call replicate_repo
            replicate_repo(&group, &repo).await.map_err(|e| {
                error!("Failed to replicate repository: {}", e);
                Status::internal(format!("Failed to replicate repository: {}", e))
            })?;
        }

        info!("Successfully replicated group: {}", group_id);
        Ok(Response::new(ReplicateGroupResponse {
            status_message: format!("Successfully replicated group: {}", group_id),
        }))
    }

    async fn list_groups(
        &self,
        _request: tonic::Request<ListGroupsRequest>,
    ) -> Result<tonic::Response<ListGroupsResponse>, tonic::Status> {
        let backend = self.backend.clone();
        let groups = backend.list_groups().await.map_err(|e| {
            error!("Failed to list groups: {}", e);
            Status::internal(format!("Failed to list groups: {}", e))
        })?;

        let group_ids: Vec<String> = groups.iter().map(|g| g.id().to_string()).collect();

        Ok(Response::new(ListGroupsResponse { group_ids }))
    }

    async fn remove_group(
        &self,
        request: tonic::Request<RemoveGroupRequest>,
    ) -> Result<tonic::Response<RemoveGroupResponse>, tonic::Status> {
        let group_id = request.into_inner().group_id;
        info!("Removing group with ID: {}", group_id);

        let group_bytes = URL_SAFE_NO_PAD.decode(&group_id).map_err(|_| {
            error!("Invalid group ID encoding");
            Status::invalid_argument("Invalid group ID encoding")
        })?;

        let group_bytes: [u8; 32] = group_bytes.try_into().map_err(|_| {
            error!("Invalid group key length");
            Status::invalid_argument("Invalid group key length")
        })?;

        let group_key = CryptoKey::new(group_bytes);

        let backend = self.backend.clone();
        backend.close_group(group_key).await.map_err(|e| {
            error!("Failed to remove group: {}", e);
            Status::internal(format!("Failed to remove group: {}", e))
        })?;

        info!("Successfully removed group: {}", group_id);
        Ok(Response::new(RemoveGroupResponse {
            status_message: format!("Successfully removed group: {}", group_id),
        }))
    }
}

async fn replicate_repo(group: &Group, repo: &Repo) -> Result<(), anyhow::Error> {
    // If the repo is not writable, attempt to download the entire collection.
    if !repo.can_write() {
        let collection_hash = repo.get_hash_from_dht().await?;
        if !group.has_hash(&collection_hash).await? {
            // Use our custom function for downloading the collection from peers
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

impl DHTEntity for RpcService {
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
