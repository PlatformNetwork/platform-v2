//! # DEPRECATED - Use validator-decentralized Instead
//!
//! This centralized validator is deprecated. For new deployments, use:
//! ```
//! validator-decentralized --data-dir /data --listen-addr /ip4/0.0.0.0/tcp/9000
//! ```
//!
//! The decentralized validator operates in P2P mode. It uses libp2p gossipsub
//! for consensus and Kademlia DHT for peer discovery.
//!
//! ---
//!
//! # Validator Node - Centralized Architecture (Legacy)
//!
//! All communication via platform-server.
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

    /// Get weights with timeout (max 3 attempts, 10s timeout each)
    /// Returns hotkey-based weights: Vec<(hotkey, weight_f64)>
    /// Returns error after 3 failed attempts instead of blocking forever
    pub async fn get_weights(&self, challenge_id: &str, epoch: u64) -> Result<Vec<(String, f64)>> {
        let url = format!(
            "{}/api/v1/challenges/{}/get_weights?epoch={}",
            self.base_url, challenge_id, epoch
        );

        const MAX_ATTEMPTS: u64 = 3;
        const TIMEOUT_SECS: u64 = 10;
        const RETRY_DELAY_SECS: u64 = 5;

        for attempt in 1..=MAX_ATTEMPTS {
            match tokio::time::timeout(
                Duration::from_secs(TIMEOUT_SECS),
                self.client.get(&url).send(),
            )
            .await
            {
                Ok(Ok(resp)) if resp.status().is_success() => {
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
                                "Failed to parse weights response for {}: {} (attempt {}/{})",
                                challenge_id, e, attempt, MAX_ATTEMPTS
                            );
                        }
                    }
                }
                Ok(Ok(resp)) => {
                    warn!(
                        "Failed to get weights for {}: {} (attempt {}/{})",
                        challenge_id,
                        resp.status(),
                        attempt,
                        MAX_ATTEMPTS
                    );
                }
                Ok(Err(e)) => {
                    warn!(
                        "Request error getting weights for {}: {} (attempt {}/{})",
                        challenge_id, e, attempt, MAX_ATTEMPTS
                    );
                }
                Err(_) => {
                    warn!(
                        "Timeout getting weights for {} after {}s (attempt {}/{})",
                        challenge_id, TIMEOUT_SECS, attempt, MAX_ATTEMPTS
                    );
                }
            }

            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
            }
        }

        Err(anyhow::anyhow!(
            "Failed to get weights for {} after {} attempts",
            challenge_id,
            MAX_ATTEMPTS
        ))
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

    #[arg(long, env = "PLATFORM_SERVER_URL")]
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
        allow_unauthenticated: false, // Require authentication in production
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
    let bittensor_client_for_metagraph: Option<Arc<BittensorClient>>;

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
                let bittensor_client_for_sync = bittensor_client.clone();
                bittensor_client_for_metagraph = Some(bittensor_client.clone());
                if let Err(e) = sync.connect(bittensor_client_for_sync).await {
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
                bittensor_client_for_metagraph = None;
            }
        }
    } else {
        info!("Bittensor: disabled");
        subtensor = None;
        subtensor_signer = None;
        subtensor_client = None;
        bittensor_client_for_metagraph = None;
    }

    info!("Validator running. Ctrl+C to stop.");

    let netuid = args.netuid;
    let version_key = args.version_key;
    let subtensor_endpoint = args.subtensor_endpoint.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut metrics_interval = tokio::time::interval(Duration::from_secs(5));
    let mut challenge_refresh_interval = tokio::time::interval(Duration::from_secs(60));
    let mut metagraph_refresh_interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

    // Track Bittensor connection state for reconnection
    let mut bittensor_disconnected = false;
    let mut last_reconnect_attempt = std::time::Instant::now();
    let mut reconnect_failures: u32 = 0;

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

    // Spawn a task to submit weights on startup if needed (after 2 minute delay)
    // This handles the case where validator starts mid-epoch and misses CommitWindowOpen
    if let (Some(ref st), Some(ref sig), Some(ref client)) = (
        subtensor.clone(),
        subtensor_signer.clone(),
        subtensor_client.clone(),
    ) {
        let st_clone = st.clone();
        let sig_clone = sig.clone();
        let client_clone = client.clone();
        let platform_client_clone = platform_client.clone();
        let cached_challenges_clone = cached_challenges.clone();

        tokio::spawn(async move {
            // Wait 2 minutes for everything to initialize
            info!("Will check for missed weights submission in 2 minutes...");
            tokio::time::sleep(Duration::from_secs(120)).await;

            // Check if we have pending commits (means we already submitted this epoch)
            if !st_clone.has_pending_commits().await {
                info!("No pending commits found - submitting weights for current epoch");

                // Get current epoch estimate
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / 12;

                submit_weights_for_epoch(
                    epoch,
                    &platform_client_clone,
                    &st_clone,
                    &sig_clone,
                    &client_clone,
                    &cached_challenges_clone,
                    netuid,
                    version_key,
                )
                .await;
            } else {
                info!("Pending commits found - weights already submitted for this epoch");
            }
        });
    }

    loop {
        tokio::select! {
            Some(event) = async {
                match block_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                // Track disconnection state for reconnection logic
                match &event {
                    BlockSyncEvent::Disconnected(msg) => {
                        bittensor_disconnected = true;
                        // Force immediate reconnect if client needs full restart
                        if msg.contains("restart required") || msg.contains("connection closed") {
                            last_reconnect_attempt = std::time::Instant::now() - Duration::from_secs(121);
                        }
                    }
                    BlockSyncEvent::Reconnected | BlockSyncEvent::NewBlock { .. } => {
                        bittensor_disconnected = false;
                        reconnect_failures = 0;
                    }
                    _ => {}
                }

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

                // Check if we need to attempt Bittensor reconnection with exponential backoff
                // Base delay: 10s, doubles on each failure, max 120s
                let backoff_secs = std::cmp::min(10 * 2u64.pow(reconnect_failures), 120);
                if bittensor_disconnected && last_reconnect_attempt.elapsed() > Duration::from_secs(backoff_secs) {
                    last_reconnect_attempt = std::time::Instant::now();
                    info!("Attempting Bittensor reconnection (attempt {}, next backoff {}s)...", reconnect_failures + 1, backoff_secs * 2);

                    // Try to reconnect by creating a new BlockSync
                    match BittensorClient::new(&subtensor_endpoint).await {
                        Ok(new_client) => {
                            let mut sync = BlockSync::new(BlockSyncConfig {
                                netuid,
                                ..Default::default()
                            });

                            if let Some(new_rx) = sync.take_event_receiver() {
                                let new_client = Arc::new(new_client);
                                match sync.connect(new_client.clone()).await {
                                    Ok(()) => {
                                        // Spawn the sync task to keep it running
                                        tokio::spawn(async move {
                                            if let Err(e) = sync.start().await {
                                                error!("Block sync error after reconnect: {}", e);
                                            }
                                        });

                                        info!("Bittensor reconnected successfully");
                                        block_rx = Some(new_rx);
                                        bittensor_disconnected = false;
                                        reconnect_failures = 0;

                                        // Also refresh metagraph with new client
                                        if let Some(ref st_client) = subtensor_client {
                                            if let Ok(mg) = sync_metagraph(&new_client, netuid).await {
                                                info!("Metagraph refreshed after reconnect: {} neurons", mg.n);
                                                let mut client = st_client.write();
                                                client.set_metagraph(mg);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to connect block sync: {}", e);
                                        reconnect_failures = reconnect_failures.saturating_add(1);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            reconnect_failures = reconnect_failures.saturating_add(1);
                            let next_backoff = std::cmp::min(10 * 2u64.pow(reconnect_failures), 120);
                            warn!("Bittensor reconnection failed: {} (will retry in {}s)", e, next_backoff);
                        }
                    }
                }
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

            _ = metagraph_refresh_interval.tick() => {
                // Re-sync metagraph to pick up new miners
                if let (Some(ref bt_client), Some(ref st_client)) = (&bittensor_client_for_metagraph, &subtensor_client) {
                    match sync_metagraph(bt_client, netuid).await {
                        Ok(mg) => {
                            info!("Metagraph refreshed: {} neurons", mg.n);
                            let mut client = st_client.write();
                            client.set_metagraph(mg);
                        }
                        Err(e) => {
                            warn!("Metagraph refresh failed: {}", e);
                        }
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

/// Submit weights for a given epoch
/// This is the core weight submission logic, extracted to be reusable
#[allow(clippy::too_many_arguments)]
async fn submit_weights_for_epoch(
    epoch: u64,
    platform_client: &Arc<PlatformServerClient>,
    st: &Arc<Subtensor>,
    sig: &Arc<BittensorSigner>,
    client: &Arc<RwLock<SubtensorClient>>,
    cached_challenges: &Arc<RwLock<Vec<ChallengeInfo>>>,
    netuid: u16,
    version_key: u64,
) {
    info!("=== SUBMITTING WEIGHTS for epoch {} ===", epoch);

    // Get weights from platform-server using cached challenges
    let challenges = cached_challenges.read().clone();
    let mechanism_weights = if !challenges.is_empty() {
        // Collect weights per mechanism using f64 for accurate accumulation
        let mut mechanism_uid_weights: HashMap<u8, HashMap<u16, f64>> = HashMap::new();

        for challenge in challenges.iter() {
            if !challenge.is_healthy {
                info!(
                    "Challenge {} is unhealthy - skipping (chain keeps existing weights)",
                    challenge.id
                );
                continue;
            }

            let mech_id = challenge.mechanism_id as u8;
            let emission_weight = challenge.emission_weight.clamp(0.0, 1.0);

            match platform_client.get_weights(&challenge.id, epoch).await {
                Ok(w) if !w.is_empty() => {
                    let uid_weights = mechanism_uid_weights.entry(mech_id).or_default();
                    let client_guard = client.read();
                    let mut resolved_count = 0usize;
                    let mut unresolved_count = 0usize;

                    for (hotkey, weight_f64) in &w {
                        let scaled_weight = weight_f64 * emission_weight;

                        if let Some(uid) = client_guard.get_uid_for_hotkey(hotkey) {
                            *uid_weights.entry(uid).or_insert(0.0) += scaled_weight;
                            resolved_count += 1;
                            info!(
                                "  [{}] {} -> UID {} (weight: {:.4} * {:.2} = {:.4})",
                                challenge.id,
                                &hotkey[..16.min(hotkey.len())],
                                uid,
                                weight_f64,
                                emission_weight,
                                scaled_weight
                            );
                        } else {
                            *uid_weights.entry(0).or_insert(0.0) += scaled_weight;
                            unresolved_count += 1;
                            warn!(
                                "  [{}] {} not in metagraph -> UID 0 (burn: {:.4})",
                                challenge.id,
                                &hotkey[..16.min(hotkey.len())],
                                scaled_weight
                            );
                        }
                    }
                    drop(client_guard);

                    if unresolved_count > 0 {
                        warn!(
                            "Challenge {}: {} hotkeys resolved, {} unresolved (sent to burn)",
                            challenge.id, resolved_count, unresolved_count
                        );
                    }

                    let weights_sum: f64 = w.iter().map(|(_, w)| w).sum();
                    let unallocated = (1.0 - weights_sum.min(1.0)) * emission_weight;
                    if unallocated > 0.001 {
                        *uid_weights.entry(0).or_insert(0.0) += unallocated;
                        info!(
                            "  [{}] Unallocated -> UID 0 (burn: {:.4})",
                            challenge.id, unallocated
                        );
                    }

                    info!(
                        "Challenge {} (mech {}, emission={:.2}): collected weights",
                        challenge.id, mech_id, emission_weight
                    );
                }
                Ok(_) => {
                    let uid_weights = mechanism_uid_weights.entry(mech_id).or_default();
                    *uid_weights.entry(0).or_insert(0.0) += emission_weight;
                    info!(
                        "Challenge {} returned empty weights - {:.4} burn to UID 0",
                        challenge.id, emission_weight
                    );
                }
                Err(e) => {
                    let uid_weights = mechanism_uid_weights.entry(mech_id).or_default();
                    *uid_weights.entry(0).or_insert(0.0) += emission_weight;
                    warn!(
                        "Failed to get weights for {} - {:.4} burn to UID 0: {}",
                        challenge.id, emission_weight, e
                    );
                }
            }
        }

        // Add missing emission to burn
        let total_emission: f64 = challenges
            .iter()
            .filter(|c| c.is_healthy)
            .map(|c| c.emission_weight.clamp(0.0, 1.0))
            .sum();

        if total_emission < 0.999 {
            let missing_emission = 1.0 - total_emission;
            info!(
                "Total emission from healthy challenges: {:.4}, adding {:.4} to burn",
                total_emission, missing_emission
            );
            if mechanism_uid_weights.is_empty() {
                mechanism_uid_weights
                    .entry(0)
                    .or_default()
                    .insert(0, missing_emission);
            } else if let Some((_, uid_weights)) = mechanism_uid_weights.iter_mut().next() {
                *uid_weights.entry(0).or_insert(0.0) += missing_emission;
            }
        }

        // Convert to Vec<(mech, uids, weights_u16)>
        let mut weights: Vec<(u8, Vec<u16>, Vec<u16>)> = Vec::new();

        for (mech_id, uid_weights) in mechanism_uid_weights {
            if uid_weights.is_empty() {
                continue;
            }

            let total: f64 = uid_weights.values().sum();
            if total <= 0.0 {
                warn!(
                    "Mechanism {} has zero total weight - sending 100% burn",
                    mech_id
                );
                weights.push((mech_id, vec![0u16], vec![65535u16]));
                continue;
            }

            let uids: Vec<u16> = uid_weights.keys().copied().collect();
            let vals_f64: Vec<f64> = uids
                .iter()
                .map(|uid| uid_weights.get(uid).copied().unwrap_or(0.0) / total)
                .collect();

            let max_val = vals_f64.iter().cloned().fold(0.0_f64, f64::max);
            let vals: Vec<u16> = if max_val > 0.0 {
                vals_f64
                    .iter()
                    .map(|v| ((v / max_val) * 65535.0).round() as u16)
                    .collect()
            } else {
                vec![0u16; uids.len()]
            };

            info!(
                "Mechanism {}: {} UIDs, total_weight={:.4} (normalized & max-upscaled)",
                mech_id,
                uids.len(),
                total
            );
            debug!("  UIDs: {:?}, Weights: {:?}", uids, vals);
            weights.push((mech_id, uids, vals));
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

    // Submit each mechanism via Subtensor with retry
    for (mechanism_id, uids, weights) in weights_to_submit {
        let mut success = false;
        for attempt in 1..=3 {
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
                    success = true;
                    break;
                }
                Ok(resp) => {
                    warn!(
                        "Mechanism {} issue (attempt {}): {}",
                        mechanism_id, attempt, resp.message
                    );
                }
                Err(e) => {
                    error!(
                        "Mechanism {} failed (attempt {}): {}",
                        mechanism_id, attempt, e
                    );
                }
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        if !success {
            error!(
                "Mechanism {} weights failed after 3 attempts - will retry next epoch",
                mechanism_id
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
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
                submit_weights_for_epoch(
                    epoch,
                    platform_client,
                    st,
                    sig,
                    client,
                    cached_challenges,
                    netuid,
                    version_key,
                )
                .await;
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
