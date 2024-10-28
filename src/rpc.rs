use crate::backend::Backend;
use crate::common::DHTEntity;
use crate::group::Group;
use crate::repo::Repo;

use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use anyhow::Result;
use tracing::{error, info};
use veilid_core::CryptoKey;
use anyhow::anyhow;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use iroh_blobs::Hash;

use tonic_reflection::server::Builder;

pub mod rpc {
    tonic::include_proto!("rpc");

    pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("descriptor");
}

pub struct RpcService {
    backend: Arc<Mutex<Backend>>,
}

pub async fn start_rpc_server(backend: Arc<Mutex<Backend>>, addr: &str) -> Result<()> {
    let rpc_service = RpcService { backend };

    // Build the reflection service
    let reflection_service = Builder::configure()
       .register_encoded_file_descriptor_set(rpc::FILE_DESCRIPTOR_SET)
       .build_v1()?;

    Server::builder()
        .add_service(rpc::rpc_server::RpcServer::new(rpc_service))
        .add_service(reflection_service) 
        .serve(addr.parse()?)
        .await?;
    Ok(())
}

#[tonic::async_trait]
impl rpc::rpc_server::Rpc for RpcService {
    async fn replicate_group(
        &self,
        request: Request<rpc::ReplicateGroupRequest>,
    ) -> Result<Response<rpc::ReplicateGroupResponse>, Status> {
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

        let backend = self.backend.lock().await;
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
        Ok(Response::new(rpc::ReplicateGroupResponse {
            status_message: format!("Successfully replicated group: {}", group_id),
        }))
    }
}

async fn replicate_repo(group: &Group, repo: &Repo) -> Result<(), anyhow::Error> {
    // If the repo is not writable, attempt to download it.
    if !repo.can_write() {
        let collection_hash = repo.get_hash_from_dht().await?;
        if !group.has_hash(&collection_hash).await? {
            // Use our custom function instead
            download(group, &collection_hash).await?;
        }
    }

    // List the files in the repo
    let files = repo.list_files().await?;

    for file_name in files {
        info!("Processing file: {}", file_name);

        let file_hash = repo.get_file_hash(&file_name).await?;
        if !repo.can_write() {
            if !group.has_hash(&file_hash).await? {
                // Use our custom function here as well
                download(group, &file_hash).await?;
            }
        }

        // Attempt to retrieve the file data stream
        let _file_data = repo.get_file_stream(&file_name).await?;
        info!("Successfully replicated file: {}", file_name);
    }

    Ok(())
}

async fn download(group: &Group, hash: &Hash) -> Result<()> {
    // Use `list_repos` instead of `list_peer_repos` to avoid `ThreadRng`
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