use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use veilid_core::{UpdateCallback, VeilidAPI, VeilidUpdate};

#[derive(Parser, Debug)]
#[command(
    name = "veilid-probe",
    about = "Quick Veilid/Save backend probe to identify bottlenecks (startup/attach/route/DHT/iroh)."
)]
struct Args {
    /// Directory to store Veilid and iroh state (protected_store/table_store/block_store/iroh)
    #[arg(long)]
    base_dir: Option<PathBuf>,

    /// Veilid namespace (defaults to a unique timestamped value)
    #[arg(long)]
    namespace: Option<String>,

    /// Max time to wait for Veilid attachment updates before proceeding/failing
    #[arg(long, default_value = "180")]
    attach_timeout_secs: u64,

    /// If set, require `public_internet_ready` (otherwise only requires `is_attached()`)
    #[arg(long, default_value_t = false)]
    require_public_internet_ready: bool,

    /// Skip route creation probe
    #[arg(long, default_value_t = false)]
    skip_route: bool,

    /// Skip backend/group/repo/upload probes (only measures Veilid startup/attach)
    #[arg(long, default_value_t = false)]
    only_startup: bool,
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn unique_namespace(prefix: &str) -> String {
    format!("{prefix}-{}", now_millis())
}

async fn init_veilid_with_logging(
    base_dir: &PathBuf,
    namespace: String,
    attach_timeout: Duration,
    require_public_internet_ready: bool,
) -> Result<(VeilidAPI, broadcast::Receiver<VeilidUpdate>)> {
    let config = save_dweb_backend::common::config_for_dir(base_dir.clone(), namespace);

    let (tx, mut rx) = broadcast::channel(256);
    let update_callback: UpdateCallback = std::sync::Arc::new(move |update| {
        let tx = tx.clone();
        tokio::spawn(async move {
            // Best-effort; receiver might not exist yet.
            let _ = tx.send(update);
        });
    });

    let t0 = tokio::time::Instant::now();
    let veilid = veilid_core::api_startup(update_callback, config)
        .await
        .context("veilid api_startup failed")?;
    info!("probe: api_startup ok in {:?}", t0.elapsed());

    let t1 = tokio::time::Instant::now();
    veilid.attach().await.context("veilid attach failed")?;
    info!("probe: attach() returned in {:?}", t1.elapsed());

    // Drain updates until attached (and optionally public-internet-ready).
    let t2 = tokio::time::Instant::now();
    let mut seen_attachment = false;
    tokio::time::timeout(attach_timeout, async {
        while let Ok(update) = rx.recv().await {
            match &update {
                VeilidUpdate::Attachment(a) => {
                    seen_attachment = true;
                    debug!(
                        "probe: attachment update: state={:?} public_internet_ready={}",
                        a.state, a.public_internet_ready
                    );

                    let attached = a.state.is_attached();
                    let public_ready = a.public_internet_ready;
                    if attached && (!require_public_internet_ready || public_ready) {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                other => debug!("probe: update: {other:?}"),
            }
        }
        Err(anyhow!("update channel closed before readiness observed"))
    })
    .await
    .map_err(|_| anyhow!("Timeout waiting for Veilid readiness"))??;
    info!(
        "probe: readiness observed in {:?} (require_public_internet_ready={})",
        t2.elapsed(),
        require_public_internet_ready
    );
    if !seen_attachment {
        warn!("probe: no Attachment updates observed before readiness");
    }

    Ok((veilid, rx))
}

async fn read_all(mut rx: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(item) = rx.recv().await {
        let chunk = item.context("stream chunk error")?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Enable `RUST_LOG=...` (Veilid uses tracing).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let base_dir = args.base_dir.unwrap_or_else(|| {
        // Default to a unique dir under /tmp so repeated runs don't collide.
        let mut p = std::env::temp_dir();
        p.push(format!("save-dweb-veilid-probe-{}", now_millis()));
        p
    });
    let namespace = args.namespace.unwrap_or_else(|| unique_namespace("save-dweb-probe"));

    tokio::fs::create_dir_all(&base_dir)
        .await
        .with_context(|| format!("failed to create base dir {}", base_dir.display()))?;

    info!("probe: base_dir={}", base_dir.display());
    info!("probe: namespace={namespace}");
    info!(
        "probe: attach_timeout_secs={} require_public_internet_ready={}",
        args.attach_timeout_secs, args.require_public_internet_ready
    );

    let (veilid_api, update_rx) = init_veilid_with_logging(
        &base_dir,
        namespace,
        Duration::from_secs(args.attach_timeout_secs),
        args.require_public_internet_ready,
    )
    .await?;

    if args.only_startup {
        info!("probe: only_startup requested, exiting");
        return Ok(());
    }

    if !args.skip_route {
        let t = tokio::time::Instant::now();
        let (_route_id, _route_blob) =
            save_dweb_backend::common::make_route(&veilid_api).await.context("make_route failed")?;
        info!("probe: make_route ok in {:?}", t.elapsed());
    }

    // Backend probe: this also creates its own route + initializes VeilidIrohBlobs.
    let store = iroh_blobs::store::fs::Store::load(base_dir.join("iroh"))
        .await
        .context("failed to load iroh store")?;

    let t_backend = tokio::time::Instant::now();
    let backend = save_dweb_backend::backend::Backend::from_dependencies(
        &base_dir,
        veilid_api,
        update_rx,
        store,
    )
    .await
    .context("Backend::from_dependencies failed")?;
    info!("probe: Backend::from_dependencies ok in {:?}", t_backend.elapsed());

    let t_group = tokio::time::Instant::now();
    let mut group = backend.create_group().await.context("create_group failed")?;
    info!("probe: create_group ok in {:?} (group_id={:?})", t_group.elapsed(), group.id());

    let t_repo = tokio::time::Instant::now();
    let repo = group.create_repo().await.context("create_repo failed")?;
    info!("probe: create_repo ok in {:?} (repo_id={:?})", t_repo.elapsed(), repo.id());

    // Local upload + local read-back (no P2P). This tells us if iroh/store/encryption is slow.
    let file_name = "probe.txt";
    let payload = b"hello from veilid-probe\n".to_vec();
    let t_up = tokio::time::Instant::now();
    let hash = repo
        .upload(file_name, payload.clone())
        .await
        .context("upload failed")?;
    info!("probe: upload ok in {:?} (hash={hash})", t_up.elapsed());

    let t_read = tokio::time::Instant::now();
    let stream = group
        .get_stream_from_hash(&hash)
        .await
        .context("get_stream_from_hash failed")?;
    let got = read_all(stream).await.context("readback failed")?;
    info!("probe: readback ok in {:?} (bytes={})", t_read.elapsed(), got.len());
    if got != payload {
        warn!(
            "probe: readback mismatch: expected {} bytes, got {} bytes",
            payload.len(),
            got.len()
        );
    }

    let t_stop = tokio::time::Instant::now();
    backend.stop().await.context("backend.stop failed")?;
    info!("probe: backend.stop ok in {:?}", t_stop.elapsed());

    Ok(())
}
