#![recursion_limit = "256"]
use crate::backend::Backend;
use crate::common::{init_veilid, CommonKeypair, DHTEntity};
use crate::constants::{UNABLE_TO_GET_GROUP_NAME, UNABLE_TO_SET_GROUP_NAME};
use crate::group::Group;
use crate::repo::Repo;
use crate::rpc::{JoinGroupRequest, RemoveGroupRequest};
use crate::rpc::{RpcClient, RpcService};
use anyhow::{anyhow, Result};
use clap::{Arg, ArgAction, Command, Subcommand};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::error;
use xdg::BaseDirectories;

mod backend;
mod common;
mod constants;
mod group;
mod repo;
mod rpc;

#[derive(Subcommand)]
enum Commands {
    Join {
        #[arg(long)]
        group_url: String,
    },
    Remove {
        #[arg(long)]
        group_id: String,
    },
    List,
    Start,
}

async fn setup_rpc_client(
    base_dir: &std::path::Path,
    backend_url: &str,
) -> anyhow::Result<RpcClient> {
    let (veilid_api, _update_rx) =
        init_veilid(base_dir, "save-dweb-backup-client".to_string()).await?;
    RpcClient::from_veilid(veilid_api, backend_url).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Command::new("Save DWeb Backend")
        .arg(
            Arg::new("backend_url")
                .long("backend-url")
                .help("URL of the backend")
                .required(false)
                .global(true),
        )
        .subcommand(
            Command::new("join").about("Join a group").arg(
                Arg::new("group_url")
                    .long("group-url")
                    .help("URL of the group to join")
                    .required(true),
            ),
        )
        .subcommand(
            Command::new("remove").about("Remove a group").arg(
                Arg::new("group_id")
                    .long("group-id")
                    .help("ID of the group to remove")
                    .required(true),
            ),
        )
        .subcommand(Command::new("list").about("List known groups"))
        .subcommand(Command::new("start").about("Start the RPC service and log the URL"))
        .get_matches();

    let backend_url = matches.get_one::<String>("backend_url");

    let xdg_dirs = BaseDirectories::with_prefix("save-dweb-backend")?;
    let base_dir = xdg_dirs.get_data_home();

    fs::create_dir_all(&base_dir)
        .await
        .expect("Failed to create base directory");

    let mut backend = Backend::new(&base_dir)?;

    match matches.subcommand() {
        Some(("join", sub_matches)) => {
            let backend_url = matches.get_one::<String>("backend_url").ok_or_else(|| {
                anyhow!("Error: --backend-url is required for the 'join' command")
            })?;

            let group_url = sub_matches.get_one::<String>("group_url").unwrap();
            println!("Joining group: {group_url}");

            let rpc_client = setup_rpc_client(&base_dir, backend_url).await?;

            rpc_client.join_group(group_url.to_string()).await?;
            println!("Successfully joined group.");
        }
        Some(("list", _)) => {
            let backend_url = matches.get_one::<String>("backend_url").ok_or_else(|| {
                anyhow!("Error: --backend-url is required for the 'list' command")
            })?;

            println!("Listing all groups...");

            let rpc_client = setup_rpc_client(&base_dir, backend_url).await?;

            let response = rpc_client.list_groups().await?;
            for group_id in response.group_ids {
                println!("Group ID: {group_id}");
            }
        }
        Some(("remove", sub_matches)) => {
            let backend_url = matches.get_one::<String>("backend_url").ok_or_else(|| {
                anyhow!("Error: --backend-url is required for the 'remove' command")
            })?;

            let group_id = sub_matches.get_one::<String>("group_id").unwrap();
            println!("Removing group: {group_id}");

            let rpc_client = setup_rpc_client(&base_dir, backend_url).await?;

            rpc_client.remove_group(group_id.to_string()).await?;
            println!("Successfully removed group.");
        }
        Some(("start", _)) => {
            backend.start().await?;
            let rpc_service = RpcService::from_backend(&backend).await?;
            println!(
                "RPC service started at URL: {}",
                rpc_service.get_descriptor_url()
            );
            rpc_service.start_update_listener().await?;
        }
        _ => {
            // Otherwise, start the normal backend and group operations
            backend.start().await?;
            tokio::signal::ctrl_c().await?;
            backend.stop().await?;
        }
    }
    Ok(())
}
