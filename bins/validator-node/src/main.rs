//! Validator Node - Centralized Architecture
//!
//! All communication via platform-server (chain.platform.network).
//! No P2P networking. Weights submitted via Subtensor (handles CRv4 automatically).

use anyhow::Result;
use challenge_orchestrator::{ChallengeOrchestrator, OrchestratorConfig};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use platform_bittensor::{
    signer_from_seed, sync_metagraph, BittensorClient, BittensorConfig, BittensorSigner, BlockSync,
    BlockSyncConfig, BlockSyncEvent, ExtrinsicWait, Subtensor, SubtensorClient,
};
use platform_core::{production_sudo_key, ChainState, Keypair, NetworkConfig};
use platform_rpc::{RpcConfig, RpcServer};
use platform_storage::Storage;
use platform_subnet_manager::BanList;
use secure_container_runtime::{run_ws_server, ContainerBroker, SecurityPolicy, WsConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

// ==================== Platform Server Client ====================

#[derive(Clone)]
pub struct PlatformServerClient {
    base_url: String,
    client: reqwest::Client,
}

impl PlatformServerClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("HTTP client"),
        }
    }

    /// Health check with infinite retry loop (30s interval)
    pub async fn health_with_retry(&self) -> bool {
        let mut attempt = 0u64;
        loop {
            attempt += 1;
            match self
                .client
                .get(format!("{}/health", self.base_url))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    info!("Platform server connected (attempt {})", attempt);
                    return true;
                }
                Ok(r) => {
                    warn!(
                        "Platform server health check failed: {} (attempt {}, retrying in 30s)",
                        r.status(),
                        attempt
                    );
                }
                Err(e) => {
                    warn!(
                        "Platform server not reachable: {} (attempt {}, retrying in 30s)",
                        e, attempt
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub async fn health(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// List challenges with infinite retry loop (30s interval)
    pub async fn list_challenges(&self) -> Result<Vec<ChallengeInfo>> {
        let url = format!("{}/api/v1/challenges", self.base_url);
        let mut attempt = 0u64;
        loop {
            attempt += 1;
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Vec<ChallengeInfo>>().await {
                        Ok(challenges) => return Ok(challenges),
                        Err(e) => {
                            warn!(
                                "Failed to parse challenges response: {} (attempt {}, retrying in 30s)",
                                e, attempt
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "Failed to list challenges: {} (attempt {}, retrying in 30s)",
                        resp.status(),
                        attempt
                    );
                }
                Err(e) => {
                    warn!(
                        "Platform server not reachable: {} (attempt {}, retrying in 30s)",
                        e, attempt
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    /// Get weights with infinite retry loop (30s interval)
    /// Returns hotkey-based weights: Vec<(hotkey, weight_f64)>
    /// Supports both formats:
    /// - New format: { weights: [{ hotkey: "...", weight: 0.5 }] }
    /// - Legacy format: { weights: [{ uid: 1, weight: 65535 }] }
    pub async fn get_weights(&self, challenge_id: &str, epoch: u64) -> Result<Vec<(String, f64)>> {
        let url = format!(
            "{}/api/v1/challenges/{}/get_weights?epoch={}",
            self.base_url, challenge_id, epoch
        );
        let mut attempt = 0u64;
        loop {
            attempt += 1;
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => {
                            let weights = data
                                .get("weights")
                                .and_then(|w| w.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|w| {
                                            // Try new format first: { hotkey, weight: f64 }
                                            if let Some(hotkey) =
                                                w.get("hotkey").and_then(|h| h.as_str())
                                            {
                                                let weight = w
                                                    .get("weight")
                                                    .and_then(|v| v.as_f64())
                                                    .unwrap_or(0.0);
                                                return Some((hotkey.to_string(), weight));
                                            }
                                            // Legacy format: { uid, weight: u16 } - skip, not supported
                                            None
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            return Ok(weights);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse weights response: {} (attempt {}, retrying in 30s)",
                                e, attempt
                            );
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "Failed to get weights for {}: {} (attempt {}, retrying in 30s)",
                        challenge_id,
                        resp.status(),
                        attempt
                    );
                }
                Err(e) => {
                    warn!(
                        "Platform server not reachable: {} (attempt {}, retrying in 30s)",
                        e, attempt
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChallengeInfo {
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    pub mechanism_id: i32,
    #[allow(dead_code)]
    pub emission_weight: f64,
    pub is_healthy: bool,
}

// ==================== WebSocket Events ====================

/// WebSocket event from platform-server
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    #[serde(rename = "challenge_event")]
    ChallengeEvent(ChallengeCustomEvent),
    #[serde(rename = "challenge_stopped")]
    ChallengeStopped(ChallengeStoppedEvent),
    #[serde(rename = "challenge_started")]
    ChallengeStarted(ChallengeStartedEvent),
    #[serde(rename = "ping")]
    Ping,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChallengeStoppedEvent {
    pub id: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChallengeStartedEvent {
    pub id: String,
    pub endpoint: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default)]
    pub gpu_required: bool,
}

fn default_timeout() -> u64 {
    3600
}
fn default_cpu() -> f64 {
    2.0
}
fn default_memory() -> u64 {
    4096
}

/// Collect current system metrics (CPU and memory)
fn collect_system_metrics() -> (f32, u64, u64) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_percent = sys.global_cpu_usage();
    let memory_used_mb = sys.used_memory() / 1024 / 1024;
    let memory_total_mb = sys.total_memory() / 1024 / 1024;

    (cpu_percent, memory_used_mb, memory_total_mb)
}

/// Report metrics to platform server
async fn report_metrics_to_platform(
    client: &reqwest::Client,
    platform_url: &str,
    keypair: &Keypair,
    hotkey: &str,
) -> anyhow::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let (cpu_percent, memory_used_mb, memory_total_mb) = collect_system_metrics();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let message = format!("metrics:{}:{}", hotkey, timestamp);
    let signature = keypair.sign_bytes(message.as_bytes()).unwrap_or_default();
    let signature_hex = format!("0x{}", hex::encode(signature));

    let payload = serde_json::json!({
        "hotkey": hotkey,
        "signature": signature_hex,
        "timestamp": timestamp,
        "cpu_percent": cpu_percent,
        "memory_used_mb": memory_used_mb,
        "memory_total_mb": memory_total_mb,
    });

    let url = format!("{}/api/v1/validators/metrics", platform_url);

    client
        .post(&url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    debug!(
        cpu = %cpu_percent,
        mem_used = %memory_used_mb,
        mem_total = %memory_total_mb,
        "Reported metrics to platform"
    );

    Ok(())
}

/// Custom event from a challenge
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChallengeCustomEvent {
    pub challenge_id: String,
    pub event_name: String,
    pub payload: serde_json::Value,
    pub timestamp: i64,
}

// ==================== CLI ====================

#[derive(Parser, Debug)]
#[command(name = "validator-node")]
#[command(about = "Platform Validator - Centralized Architecture")]
struct Args {
    /// Secret key (hex or mnemonic)
    #[arg(short = 'k', long, env = "VALIDATOR_SECRET_KEY")]
    secret_key: Option<String>,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,

    /// Stake in TAO (for --no-bittensor mode)
    #[arg(long, default_value = "1000")]
    stake: f64,

    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    subtensor_endpoint: String,

    #[arg(long, env = "NETUID", default_value = "100")]
    netuid: u16,

    #[arg(long)]
    no_bittensor: bool,

    #[arg(long, default_value = "8080")]
    rpc_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    rpc_addr: String,

    #[arg(long, default_value = "true")]
    docker_challenges: bool,

    #[arg(long, env = "BROKER_WS_PORT", default_value = "8090")]
    broker_port: u16,

    #[arg(long, env = "BROKER_JWT_SECRET")]
    broker_jwt_secret: Option<String>,

    #[arg(
        long,
        env = "PLATFORM_SERVER_URL",
        default_value = "https://chain.platform.network"
    )]
    platform_server: String,

    #[arg(long, env = "VERSION_KEY", default_value = "1")]
    version_key: u64,
}

// ==================== Main ====================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,validator_node=debug".into()),
        )
        .init();

    let args = Args::parse();
    info!("Starting validator (centralized mode)");

    // Keypair
    let keypair = load_keypair(&args)?;
    let validator_hotkey = keypair.ss58_address();
    info!("Validator: {}", validator_hotkey);

    // Export hotkey and secret key as env vars for challenge-orchestrator
    // These are passed to challenge containers for signing LLM proxy requests
    std::env::set_var("VALIDATOR_HOTKEY", &validator_hotkey);
    if let Some(ref secret) = args.secret_key {
        std::env::set_var("VALIDATOR_SECRET_KEY", secret);
    }

    // Data dir
    std::fs::create_dir_all(&args.data_dir)?;
    let data_dir = std::fs::canonicalize(&args.data_dir)?;

    // Storage
    let storage = Storage::open(data_dir.join("validator.db"))?;
    let _storage = Arc::new(storage);

    // Chain state
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        production_sudo_key(),
        NetworkConfig::default(),
    )));
    let bans = Arc::new(RwLock::new(BanList::default()));

    // Platform server - wait until connected (infinite retry)
    let platform_client = Arc::new(PlatformServerClient::new(&args.platform_server));
    info!("Platform server: {}", args.platform_server);
    platform_client.health_with_retry().await;

    // Container broker
    info!("Container broker on port {}...", args.broker_port);
    let broker = Arc::new(ContainerBroker::with_policy(SecurityPolicy::default()).await?);

    // Use provided JWT secret or generate a random one for this session
    let jwt_secret = args.broker_jwt_secret.clone().unwrap_or_else(|| {
        let secret = uuid::Uuid::new_v4().to_string();
        info!("Generated random BROKER_JWT_SECRET for this session");
        // Set env var so challenge-orchestrator uses the same secret
        std::env::set_var("BROKER_JWT_SECRET", &secret);
        secret
    });

    let ws_config = WsConfig {
        bind_addr: format!("0.0.0.0:{}", args.broker_port),
        jwt_secret: Some(jwt_secret),
        allowed_challenges: vec![],
        max_connections_per_challenge: 10,
    };
    let broker_clone = broker.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ws_server(broker_clone, ws_config).await {
            error!("Broker error: {}", e);
        }
    });

    // Challenge orchestrator
    let orchestrator = if args.docker_challenges {
        match ChallengeOrchestrator::new(OrchestratorConfig {
            network_name: "platform-network".to_string(),
            health_check_interval: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(30),
            registry: None,
        })
        .await
        {
            Ok(o) => Some(Arc::new(o)),
            Err(e) => {
                warn!("Docker orchestrator failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // List challenges and start containers
    let challenges = platform_client.list_challenges().await?;
    if challenges.is_empty() {
        info!("No challenges registered on platform-server");
    } else {
        info!("Challenges from platform-server:");
        for ch in &challenges {
            info!(
                "  - {} (mechanism={}, healthy={})",
                ch.id, ch.mechanism_id, ch.is_healthy
            );
        }

        // Start challenge containers
        if let Some(ref orch) = orchestrator {
            for ch in &challenges {
                let docker_image = format!("ghcr.io/platformnetwork/{}:latest", ch.id);
                // Generate a deterministic UUID from challenge name
                let challenge_uuid =
                    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, ch.id.as_bytes());
                let config = challenge_orchestrator::ChallengeContainerConfig {
                    challenge_id: platform_core::ChallengeId(challenge_uuid),
                    name: ch.id.clone(),
                    docker_image,
                    mechanism_id: ch.mechanism_id as u8,
                    emission_weight: ch.emission_weight,
                    timeout_secs: 3600,
                    cpu_cores: 2.0,
                    memory_mb: 4096,
                    gpu_required: false,
                };

                info!("Starting challenge container: {}", ch.id);
                match orch.add_challenge(config).await {
                    Ok(_) => info!("Challenge container started: {}", ch.id),
                    Err(e) => error!("Failed to start challenge {}: {}", ch.id, e),
                }
            }

            // Start health monitoring
            let orch_clone = orch.clone();
            tokio::spawn(async move {
                if let Err(e) = orch_clone.start().await {
                    error!("Orchestrator health monitor error: {}", e);
                }
            });
        }
    }

    // Build challenge URL map for WebSocket event handler
    // Maps challenge name -> local container endpoint from orchestrator
    let challenge_urls: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(HashMap::new()));
    if let Some(ref orch) = orchestrator {
        for ch in &challenges {
            // Generate same deterministic UUID used when starting the container
            let challenge_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, ch.id.as_bytes());
            let challenge_id = platform_core::ChallengeId(challenge_uuid);

            // Get the actual endpoint from the orchestrator
            if let Some(instance) = orch.get_challenge(&challenge_id) {
                challenge_urls
                    .write()
                    .insert(ch.id.clone(), instance.endpoint.clone());
                info!(
                    "Challenge URL registered: {} -> {}",
                    ch.id, instance.endpoint
                );
            } else {
                warn!("Challenge {} not found in orchestrator", ch.id);
            }
        }
    }

    // Start WebSocket listener for platform-server events
    // This listens for new_submission events and triggers local evaluation
    // Also handles challenge_stopped events to stop local containers
    let ws_platform_url = args.platform_server.clone();
    let ws_keypair = keypair.clone();
    let ws_challenge_urls = challenge_urls.clone();
    let ws_orchestrator = orchestrator.clone();
    tokio::spawn(async move {
        start_websocket_listener(
            ws_platform_url,
            ws_keypair,
            ws_challenge_urls,
            ws_orchestrator,
        )
        .await;
    });

    // RPC server
    let addr: SocketAddr = format!("{}:{}", args.rpc_addr, args.rpc_port).parse()?;
    let rpc_server = RpcServer::new(
        RpcConfig {
            addr,
            netuid: args.netuid,
            name: "Platform".to_string(),
            min_stake: (args.stake * 1e9) as u64,
            cors_enabled: true,
        },
        chain_state.clone(),
        bans.clone(),
    );
    let _rpc = rpc_server.spawn();
    info!("RPC: http://{}:{}", args.rpc_addr, args.rpc_port);

    // Bittensor setup
    let subtensor: Option<Arc<Subtensor>>;
    let subtensor_signer: Option<Arc<BittensorSigner>>;
    let subtensor_client: Option<Arc<RwLock<SubtensorClient>>>;
    let mut block_rx: Option<tokio::sync::mpsc::Receiver<BlockSyncEvent>> = None;

    if !args.no_bittensor {
        info!(
            "Bittensor: {} (netuid={})",
            args.subtensor_endpoint, args.netuid
        );

        // Create Subtensor with persistence for automatic commit-reveal handling
        let state_path = data_dir.join("subtensor_state.json");
        match Subtensor::with_persistence(&args.subtensor_endpoint, state_path.clone()).await {
            Ok(st) => {
                info!("Subtensor connected with persistence at {:?}", state_path);

                // Create signer
                let secret = args.secret_key.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("VALIDATOR_SECRET_KEY required for Bittensor")
                })?;

                match signer_from_seed(secret) {
                    Ok(signer) => {
                        info!("Bittensor hotkey: {}", signer.account_id());
                        subtensor_signer = Some(Arc::new(signer));
                    }
                    Err(e) => {
                        error!("Failed to create signer: {}", e);
                        subtensor_signer = None;
                    }
                }

                subtensor = Some(Arc::new(st));

                // Create SubtensorClient for metagraph lookups (hotkey -> UID conversion)
                let mut client = SubtensorClient::new(BittensorConfig {
                    endpoint: args.subtensor_endpoint.clone(),
                    netuid: args.netuid,
                    ..Default::default()
                });

                // Sync metagraph and store client for hotkey -> UID lookups
                let bittensor_client = BittensorClient::new(&args.subtensor_endpoint).await?;
                match sync_metagraph(&bittensor_client, args.netuid).await {
                    Ok(mg) => {
                        info!("Metagraph: {} neurons", mg.n);
                        // Store metagraph in our SubtensorClient
                        client.set_metagraph(mg);
                    }
                    Err(e) => warn!("Metagraph sync failed: {}", e),
                }

                subtensor_client = Some(Arc::new(RwLock::new(client)));

                // Block sync
                let mut sync = BlockSync::new(BlockSyncConfig {
                    netuid: args.netuid,
                    ..Default::default()
                });
                let rx = sync.take_event_receiver();

                let bittensor_client = Arc::new(bittensor_client);
                if let Err(e) = sync.connect(bittensor_client).await {
                    warn!("Block sync connect failed: {}", e);
                } else {
                    tokio::spawn(async move {
                        if let Err(e) = sync.start().await {
                            error!("Block sync error: {}", e);
                        }
                    });
                    block_rx = rx;
                    info!("Block sync: started");
                }
            }
            Err(e) => {
                error!("Subtensor connection failed: {}", e);
                subtensor = None;
                subtensor_signer = None;
                subtensor_client = None;
            }
        }
    } else {
        info!("Bittensor: disabled");
        subtensor = None;
        subtensor_signer = None;
        subtensor_client = None;
    }

    info!("Validator running. Ctrl+C to stop.");

    let netuid = args.netuid;
    let version_key = args.version_key;
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut metrics_interval = tokio::time::interval(Duration::from_secs(5));
    let mut challenge_refresh_interval = tokio::time::interval(Duration::from_secs(60));

    // Store challenges in Arc<RwLock> for periodic refresh
    let cached_challenges: Arc<RwLock<Vec<ChallengeInfo>>> = Arc::new(RwLock::new(
        platform_client.list_challenges().await.unwrap_or_default(),
    ));

    // Create HTTP client and extract values for metrics reporting
    let metrics_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("HTTP client for metrics");
    let platform_url = args.platform_server.clone();
    let hotkey = keypair.ss58_address();

    loop {
        tokio::select! {
            Some(event) = async {
                match block_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                handle_block_event(
                    event,
                    &platform_client,
                    &subtensor,
                    &subtensor_signer,
                    &subtensor_client,
                    &cached_challenges,
                    netuid,
                    version_key,
                ).await;
            }

            _ = interval.tick() => {
                debug!("Heartbeat");
            }

            _ = metrics_interval.tick() => {
                if let Err(e) = report_metrics_to_platform(
                    &metrics_client,
                    &platform_url,
                    &keypair,
                    &hotkey,
                ).await {
                    debug!("Failed to report metrics: {}", e);
                }
            }

            _ = challenge_refresh_interval.tick() => {
                match platform_client.list_challenges().await {
                    Ok(new_challenges) => {
                        let mut cached = cached_challenges.write();
                        let count = new_challenges.len();
                        *cached = new_challenges;
                        info!("Refreshed {} challenges from platform-server", count);
                    }
                    Err(e) => {
                        warn!("Failed to refresh challenges: {}", e);
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    info!("Stopped.");
    Ok(())
}

fn load_keypair(args: &Args) -> Result<Keypair> {
    let secret = args
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("VALIDATOR_SECRET_KEY required"))?
        .trim();
    let hex = secret.strip_prefix("0x").unwrap_or(secret);

    if hex.len() == 64 {
        if let Ok(bytes) = hex::decode(hex) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(Keypair::from_seed(&arr)?);
            }
        }
    }
    Ok(Keypair::from_mnemonic(secret)?)
}

async fn handle_block_event(
    event: BlockSyncEvent,
    platform_client: &Arc<PlatformServerClient>,
    subtensor: &Option<Arc<Subtensor>>,
    signer: &Option<Arc<BittensorSigner>>,
    subtensor_client: &Option<Arc<RwLock<SubtensorClient>>>,
    cached_challenges: &Arc<RwLock<Vec<ChallengeInfo>>>,
    netuid: u16,
    version_key: u64,
) {
    match event {
        BlockSyncEvent::NewBlock { block_number, .. } => {
            debug!("Block {}", block_number);
        }

        BlockSyncEvent::EpochTransition {
            old_epoch,
            new_epoch,
            block,
        } => {
            info!("Epoch: {} -> {} (block {})", old_epoch, new_epoch, block);
        }

        BlockSyncEvent::CommitWindowOpen { epoch, block } => {
            info!("=== COMMIT WINDOW: epoch {} block {} ===", epoch, block);

            // Submit weights via Subtensor (handles CRv4/commit-reveal automatically)
            if let (Some(st), Some(sig), Some(client)) = (
                subtensor.as_ref(),
                signer.as_ref(),
                subtensor_client.as_ref(),
            ) {
                // Get weights from platform-server using cached challenges
                let challenges = cached_challenges.read().clone();
                let mechanism_weights = if !challenges.is_empty() {
                    let mut weights = Vec::new();

                    for challenge in challenges.iter().filter(|c| c.is_healthy) {
                        match platform_client.get_weights(&challenge.id, epoch).await {
                            Ok(w) if !w.is_empty() => {
                                // Get challenge emission weight (0.0-1.0)
                                let emission_weight = challenge.emission_weight.clamp(0.0, 1.0);

                                // Convert hotkeys to UIDs using metagraph
                                let client_guard = client.read();
                                let mut uids = Vec::new();
                                let mut vals = Vec::new();
                                let mut total_weight: f64 = 0.0;

                                for (hotkey, weight_f64) in &w {
                                    if let Some(uid) = client_guard.get_uid_for_hotkey(hotkey) {
                                        // Apply emission_weight: scale the challenge weight
                                        let scaled_weight = weight_f64 * emission_weight;
                                        // Convert f64 weight (0.0-1.0) to u16 (0-65535)
                                        let weight_u16 = (scaled_weight * 65535.0).round() as u16;
                                        uids.push(uid);
                                        vals.push(weight_u16);
                                        total_weight += scaled_weight;
                                        info!(
                                            "  {} -> UID {} (weight: {:.4} * {:.2} = {:.4} = {})",
                                            &hotkey[..16],
                                            uid,
                                            weight_f64,
                                            emission_weight,
                                            scaled_weight,
                                            weight_u16
                                        );
                                    } else {
                                        warn!(
                                            "Hotkey {} not found in metagraph, skipping",
                                            &hotkey[..16]
                                        );
                                    }
                                }
                                drop(client_guard);

                                // Add remaining weight to burn (UID 0)
                                // remaining = 1.0 - emission_weight (goes to burn)
                                let burn_weight = 1.0 - total_weight;
                                if burn_weight > 0.001 {
                                    let burn_u16 = (burn_weight * 65535.0).round() as u16;
                                    // Check if UID 0 already exists, if not add it
                                    if let Some(pos) = uids.iter().position(|&u| u == 0) {
                                        vals[pos] = vals[pos].saturating_add(burn_u16);
                                    } else {
                                        uids.push(0);
                                        vals.push(burn_u16);
                                    }
                                    info!("  Burn (UID 0): {:.4} = {}", burn_weight, burn_u16);
                                }

                                if !uids.is_empty() {
                                    info!(
                                        "Challenge {} (mech {}, emission_weight={:.2}): {} weights",
                                        challenge.id,
                                        challenge.mechanism_id,
                                        emission_weight,
                                        uids.len()
                                    );
                                    weights.push((challenge.mechanism_id as u8, uids, vals));
                                } else {
                                    warn!(
                                        "Challenge {} has weights but no UIDs resolved",
                                        challenge.id
                                    );
                                }
                            }
                            Ok(_) => debug!("Challenge {} has no weights", challenge.id),
                            Err(e) => {
                                warn!("Failed to get weights for {}: {}", challenge.id, e)
                            }
                        }
                    }

                    weights
                } else {
                    info!("No challenges cached from platform-server");
                    vec![]
                };

                // Submit weights (or burn weights if none)
                let weights_to_submit = if mechanism_weights.is_empty() {
                    info!("No weights - submitting burn weights to UID 0");
                    vec![(0u8, vec![0u16], vec![65535u16])]
                } else {
                    mechanism_weights
                };

                // Submit each mechanism via Subtensor (handles CRv4 automatically)
                for (mechanism_id, uids, weights) in weights_to_submit {
                    match st
                        .set_mechanism_weights(
                            sig,
                            netuid,
                            mechanism_id,
                            &uids,
                            &weights,
                            version_key,
                            ExtrinsicWait::Finalized,
                        )
                        .await
                    {
                        Ok(resp) if resp.success => {
                            info!(
                                "Mechanism {} weights submitted: {:?}",
                                mechanism_id, resp.tx_hash
                            );
                        }
                        Ok(resp) => {
                            warn!("Mechanism {} issue: {}", mechanism_id, resp.message);
                        }
                        Err(e) => {
                            error!("Mechanism {} failed: {}", mechanism_id, e);
                        }
                    }
                }
            } else {
                warn!("No Subtensor/signer - cannot submit weights");
            }
        }

        BlockSyncEvent::RevealWindowOpen { epoch, block } => {
            info!("=== REVEAL WINDOW: epoch {} block {} ===", epoch, block);

            // With CRv4, reveals are automatic via DRAND
            // For older versions, Subtensor handles reveals internally
            if let (Some(st), Some(sig)) = (subtensor.as_ref(), signer.as_ref()) {
                if st.has_pending_commits().await {
                    info!("Revealing pending commits...");
                    match st.reveal_all_pending(sig, ExtrinsicWait::Finalized).await {
                        Ok(results) => {
                            for resp in results {
                                if resp.success {
                                    info!("Revealed: {:?}", resp.tx_hash);
                                }
                            }
                        }
                        Err(e) => error!("Reveal failed: {}", e),
                    }
                }
            }
        }

        BlockSyncEvent::PhaseChange {
            old_phase,
            new_phase,
            ..
        } => {
            debug!("Phase: {:?} -> {:?}", old_phase, new_phase);
        }

        BlockSyncEvent::Disconnected(e) => warn!("Bittensor disconnected: {}", e),
        BlockSyncEvent::Reconnected => info!("Bittensor reconnected"),
    }
}

// ==================== WebSocket Event Listener ====================

/// Start WebSocket listener for platform-server events
/// Listens for challenge events and triggers evaluations
/// Also handles challenge_stopped events to stop local containers
pub async fn start_websocket_listener(
    platform_url: String,
    keypair: Keypair,
    challenge_urls: Arc<RwLock<HashMap<String, String>>>,
    orchestrator: Option<Arc<ChallengeOrchestrator>>,
) {
    let validator_hotkey = keypair.ss58_address();
    let keypair = Arc::new(keypair); // Wrap in Arc for sharing across tasks

    // Convert HTTP URL to WebSocket URL with authentication params
    let base_ws_url = platform_url
        .replace("https://", "wss://")
        .replace("http://", "ws://")
        + "/ws";

    info!("Starting WebSocket listener: {}", base_ws_url);

    loop {
        // Generate fresh timestamp and signature for each connection attempt
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let message = format!("ws_connect:{}:{}", validator_hotkey, timestamp);
        let signature = hex::encode(keypair.sign_bytes(message.as_bytes()).unwrap_or_default());

        let ws_url = format!(
            "{}?hotkey={}&timestamp={}&signature={}&role=validator",
            base_ws_url, validator_hotkey, timestamp, signature
        );

        match connect_to_websocket(
            &ws_url,
            keypair.clone(),
            challenge_urls.clone(),
            orchestrator.clone(),
        )
        .await
        {
            Ok(()) => {
                info!("WebSocket connection closed, reconnecting in 5s...");
            }
            Err(e) => {
                warn!("WebSocket error: {}, reconnecting in 30s...", e);
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn connect_to_websocket(
    ws_url: &str,
    keypair: Arc<Keypair>,
    challenge_urls: Arc<RwLock<HashMap<String, String>>>,
    orchestrator: Option<Arc<ChallengeOrchestrator>>,
) -> Result<()> {
    let _validator_hotkey = keypair.ss58_address();
    let (ws_stream, _) = connect_async(ws_url).await?;
    let (mut write, mut read) = ws_stream.split();

    info!("WebSocket connected to platform-server");

    // Send ping periodically to keep connection alive
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if write.send(Message::Ping(vec![])).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => match serde_json::from_str::<WsEvent>(&text) {
                Ok(WsEvent::ChallengeEvent(event)) => {
                    handle_challenge_event(event, keypair.clone(), challenge_urls.clone()).await;
                }
                Ok(WsEvent::ChallengeStopped(event)) => {
                    info!("Received challenge_stopped event for: {}", event.id);
                    if let Some(ref orch) = orchestrator {
                        // Get the ChallengeId from challenge name
                        let challenge_uuid =
                            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, event.id.as_bytes());
                        let challenge_id = platform_core::ChallengeId(challenge_uuid);
                        match orch.remove_challenge(challenge_id).await {
                            Ok(_) => info!("Challenge container stopped: {}", event.id),
                            Err(e) => {
                                warn!("Failed to stop challenge container {}: {}", event.id, e)
                            }
                        }
                        // Remove from URL map
                        challenge_urls.write().remove(&event.id);
                    } else {
                        warn!("No orchestrator available to stop challenge: {}", event.id);
                    }
                }
                Ok(WsEvent::ChallengeStarted(event)) => {
                    info!(
                        "Received challenge_started event for: {} at {} (image: {}, emission: {})",
                        event.id, event.endpoint, event.docker_image, event.emission_weight
                    );
                    // Start the challenge container locally using values from the event
                    if let Some(ref orch) = orchestrator {
                        let challenge_uuid =
                            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, event.id.as_bytes());
                        let config = challenge_orchestrator::ChallengeContainerConfig {
                            challenge_id: platform_core::ChallengeId(challenge_uuid),
                            name: event.id.clone(),
                            docker_image: event.docker_image.clone(),
                            mechanism_id: event.mechanism_id,
                            emission_weight: event.emission_weight,
                            timeout_secs: event.timeout_secs,
                            cpu_cores: event.cpu_cores,
                            memory_mb: event.memory_mb,
                            gpu_required: event.gpu_required,
                        };

                        match orch.add_challenge(config).await {
                            Ok(_) => {
                                info!("Challenge container started locally: {}", event.id);
                                // Add to URL map
                                challenge_urls
                                    .write()
                                    .insert(event.id.clone(), event.endpoint.clone());
                            }
                            Err(e) => {
                                error!("Failed to start challenge container {}: {}", event.id, e)
                            }
                        }
                    } else {
                        warn!("No orchestrator available to start challenge: {}", event.id);
                    }
                }
                Ok(WsEvent::Ping) => {
                    debug!("Received ping from server");
                }
                Ok(WsEvent::Other) => {
                    debug!("Received other event");
                }
                Err(e) => {
                    debug!("Failed to parse WebSocket message: {}", e);
                }
            },
            Ok(Message::Ping(_)) => {
                debug!("Received ping");
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket closed by server");
                break;
            }
            Err(e) => {
                warn!("WebSocket receive error: {}", e);
                break;
            }
            _ => {}
        }
    }

    ping_task.abort();
    Ok(())
}

/// Handle challenge-specific events
async fn handle_challenge_event(
    event: ChallengeCustomEvent,
    _keypair: Arc<Keypair>,
    _challenge_urls: Arc<RwLock<HashMap<String, String>>>,
) {
    // Platform validator-node is a generic orchestrator
    // Challenge-specific events are handled by challenge containers
    debug!(
        "Challenge event: {}:{} (handled by challenge container)",
        event.challenge_id, event.event_name
    );
}
