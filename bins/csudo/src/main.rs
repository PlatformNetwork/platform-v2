//! Chain Sudo (csudo) - Administrative CLI for Platform Chain
//!
//! Provides subnet owners with administrative commands for managing
//! challenges, validators, and network configuration.

use anyhow::Result;
use clap::{Parser, Subcommand};
use parking_lot::RwLock;
use platform_consensus::PBFTEngine;
use platform_core::{
    ChainState, ChallengeContainerConfig, ChallengeId, Hotkey, Keypair, MechanismWeightConfig,
    NetworkConfig, SignedNetworkMessage, Stake, SudoAction, ValidatorInfo,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "csudo")]
#[command(about = "Platform Chain administrative CLI for subnet owners")]
struct Args {
    /// Secret key or mnemonic (REQUIRED - subnet owner must be registered)
    /// Can be hex encoded 32 bytes or BIP39 mnemonic phrase
    #[arg(short, long, env = "SUDO_SECRET_KEY", required = true)]
    secret_key: String,

    /// Network peer to connect to (P2P)
    #[arg(short, long, default_value = "/ip4/127.0.0.1/tcp/9000")]
    peer: String,

    /// RPC server URL for queries
    #[arg(
        short,
        long,
        default_value = "https://chain.platform.network",
        env = "PLATFORM_RPC"
    )]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new keypair
    GenerateKey,

    /// Add a challenge (Docker container)
    AddChallenge {
        /// Challenge name
        #[arg(short, long)]
        name: String,

        /// Docker image (e.g., "ghcr.io/platformnetwork/term-challenge:37cd137")
        #[arg(short, long)]
        docker_image: String,

        /// Mechanism ID on Bittensor (1, 2, 3... - each mechanism can have multiple challenges)
        #[arg(short, long)]
        mechanism_id: u8,

        /// Timeout in seconds
        #[arg(long, default_value = "3600")]
        timeout: u64,

        /// Emission weight (0.0 - 1.0) - portion of mechanism weights this challenge receives
        #[arg(long, default_value = "1.0")]
        emission_weight: f64,

        /// CPU cores
        #[arg(long, default_value = "2.0")]
        cpu_cores: f64,

        /// Memory in MB
        #[arg(long, default_value = "4096")]
        memory_mb: u64,

        /// Requires GPU
        #[arg(long, default_value = "false")]
        gpu: bool,
    },

    /// Update a challenge (new Docker image)
    UpdateChallenge {
        /// Challenge ID (UUID)
        #[arg(short, long)]
        id: String,

        /// New Docker image
        #[arg(short, long)]
        docker_image: String,
    },

    /// Remove a challenge
    RemoveChallenge {
        /// Challenge ID (UUID)
        #[arg(short, long)]
        id: String,
    },

    /// Set challenge weight ratio on a mechanism
    SetChallengeWeight {
        /// Challenge ID (UUID)
        #[arg(short, long)]
        id: String,

        /// Mechanism ID
        #[arg(short, long)]
        mechanism_id: u8,

        /// Weight ratio (0.0 - 1.0) - if multiple challenges share a mechanism, ratios are normalized
        #[arg(short, long)]
        weight: f64,
    },

    /// Set mechanism burn rate (portion of weights that go to UID 0)
    SetMechanismBurn {
        /// Mechanism ID
        #[arg(short, long)]
        mechanism_id: u8,

        /// Burn rate (0.0 - 1.0), e.g., 0.1 = 10% to UID 0
        #[arg(short, long)]
        burn_rate: f64,
    },

    /// Configure mechanism weight distribution
    SetMechanismConfig {
        /// Mechanism ID
        #[arg(short, long)]
        mechanism_id: u8,

        /// Burn rate (0.0 - 1.0)
        #[arg(long, default_value = "0.0")]
        burn_rate: f64,

        /// Max weight cap per miner (0.0 = no cap, 0.5 = max 50%)
        #[arg(long, default_value = "0.5")]
        max_cap: f64,

        /// Minimum weight threshold (prevents dust)
        #[arg(long, default_value = "0.0001")]
        min_threshold: f64,

        /// Equal distribution among challenges (vs per-challenge ratios)
        #[arg(long, default_value = "false")]
        equal_distribution: bool,
    },

    /// Set required validator version
    SetVersion {
        /// Minimum required version (e.g., "0.2.0")
        #[arg(short, long)]
        version: String,

        /// Docker image for validators
        #[arg(short, long)]
        docker_image: String,

        /// Mandatory update (validators must update)
        #[arg(long, default_value = "false")]
        mandatory: bool,

        /// Deadline block (optional)
        #[arg(long)]
        deadline_block: Option<u64>,
    },

    /// List challenges (query from network)
    ListChallenges,

    /// List mechanism configurations
    ListMechanisms,

    /// Add a validator
    AddValidator {
        /// Validator hotkey (hex)
        #[arg(short, long)]
        hotkey: String,

        /// Stake amount in TAO
        #[arg(short, long, default_value = "10")]
        stake: f64,
    },

    /// Remove a validator
    RemoveValidator {
        /// Validator hotkey (hex)
        #[arg(short, long)]
        hotkey: String,
    },

    /// Update network configuration
    UpdateConfig {
        /// Minimum stake in TAO
        #[arg(long)]
        min_stake: Option<f64>,

        /// Consensus threshold (0.0-1.0)
        #[arg(long)]
        threshold: Option<f64>,

        /// Block time in milliseconds
        #[arg(long)]
        block_time: Option<u64>,
    },

    /// Emergency pause the network
    Pause {
        /// Reason for pause
        #[arg(short, long)]
        reason: String,
    },

    /// Resume the network
    Resume,

    /// Show network status
    Status,
}

/// Derive keypair from BIP39 mnemonic using sr25519 (Substrate/Bittensor standard)
fn derive_keypair_from_mnemonic(mnemonic_str: &str) -> Result<Keypair> {
    let keypair = Keypair::from_mnemonic(mnemonic_str)?;

    info!("Derived sr25519 keypair from mnemonic");
    info!("Hotkey: {}", keypair.hotkey().to_hex());
    info!("SS58 Address: {}", keypair.ss58_address());

    Ok(keypair)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();

    // Handle generate-key command separately
    if let Commands::GenerateKey = args.command {
        let keypair = Keypair::generate();
        println!("Generated new sr25519 keypair:");
        println!("  Hotkey (hex):   {}", keypair.hotkey().to_hex());
        println!("  SS58 Address:   {}", keypair.ss58_address());
        println!("  Seed (secret):  {}", hex::encode(keypair.seed()));
        println!();
        println!("To use with csudo (use mnemonic or seed):");
        println!("  export SUDO_SECRET_KEY=\"your 24-word mnemonic phrase\"");
        return Ok(());
    }

    // Parse secret key (hex seed or mnemonic)
    let keypair = {
        let secret = args.secret_key.trim();

        // Strip 0x prefix if present
        let hex_str = secret.strip_prefix("0x").unwrap_or(secret);

        // Try hex decode first (64 hex chars = 32 bytes seed)
        if hex_str.len() == 64 {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    info!("Loaded sr25519 keypair from hex seed");
                    Keypair::from_seed(&arr)?
                } else {
                    anyhow::bail!("Hex seed must be 32 bytes");
                }
            } else {
                // Not valid hex, try as mnemonic
                derive_keypair_from_mnemonic(secret)?
            }
        } else {
            // Assume it's a mnemonic phrase
            derive_keypair_from_mnemonic(secret)?
        }
    };

    info!("Subnet owner SS58: {}", keypair.ss58_address());
    info!("Hotkey (hex): {}", keypair.hotkey().to_hex());

    // Create a temporary chain state (we'll sync from network)
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        keypair.hotkey(),
        NetworkConfig::default(),
    )));

    // Create message channel
    let (msg_tx, mut msg_rx) = mpsc::channel::<SignedNetworkMessage>(100);

    // Create consensus engine
    let consensus = PBFTEngine::new(keypair.clone(), chain_state.clone(), msg_tx);

    // Execute command
    let action = match args.command {
        Commands::GenerateKey => unreachable!(),

        Commands::AddChallenge {
            name,
            docker_image,
            mechanism_id,
            timeout,
            emission_weight,
            cpu_cores,
            memory_mb,
            gpu,
        } => {
            let config = ChallengeContainerConfig {
                challenge_id: ChallengeId::new(),
                name: name.clone(),
                docker_image: docker_image.clone(),
                mechanism_id,
                emission_weight,
                timeout_secs: timeout,
                cpu_cores,
                memory_mb,
                gpu_required: gpu,
            };

            info!(
                "Adding challenge: {} (image: {}, mechanism: {}, weight: {:.0}%)",
                name,
                docker_image,
                mechanism_id,
                emission_weight * 100.0
            );
            SudoAction::AddChallenge { config }
        }

        Commands::UpdateChallenge { id, docker_image } => {
            let challenge_id = ChallengeId(uuid::Uuid::parse_str(&id)?);
            info!("Updating challenge {} to image {}", id, docker_image);

            let config = ChallengeContainerConfig {
                challenge_id,
                name: format!("challenge-{}", &id[..8]),
                docker_image,
                mechanism_id: 1,
                emission_weight: 1.0,
                timeout_secs: 3600,
                cpu_cores: 2.0,
                memory_mb: 4096,
                gpu_required: false,
            };

            SudoAction::UpdateChallenge { config }
        }

        Commands::RemoveChallenge { id } => {
            let challenge_id = ChallengeId(uuid::Uuid::parse_str(&id)?);
            info!("Removing challenge: {}", id);
            SudoAction::RemoveChallenge { id: challenge_id }
        }

        Commands::SetChallengeWeight {
            id,
            mechanism_id,
            weight,
        } => {
            let challenge_id = ChallengeId(uuid::Uuid::parse_str(&id)?);
            info!(
                "Setting challenge {} weight on mechanism {} to {:.2}%",
                id,
                mechanism_id,
                weight * 100.0
            );
            SudoAction::SetChallengeWeight {
                challenge_id,
                mechanism_id,
                weight_ratio: weight,
            }
        }

        Commands::SetMechanismBurn {
            mechanism_id,
            burn_rate,
        } => {
            info!(
                "Setting mechanism {} burn rate to {:.2}%",
                mechanism_id,
                burn_rate * 100.0
            );
            SudoAction::SetMechanismBurnRate {
                mechanism_id,
                burn_rate,
            }
        }

        Commands::SetMechanismConfig {
            mechanism_id,
            burn_rate,
            max_cap,
            min_threshold,
            equal_distribution,
        } => {
            let config = MechanismWeightConfig {
                mechanism_id,
                base_burn_rate: burn_rate,
                equal_distribution,
                min_weight_threshold: min_threshold,
                max_weight_cap: max_cap,
                active: true,
            };
            info!(
                "Setting mechanism {} config: burn={:.2}%, cap={:.2}%, equal={}",
                mechanism_id,
                burn_rate * 100.0,
                max_cap * 100.0,
                equal_distribution
            );
            SudoAction::SetMechanismConfig {
                mechanism_id,
                config,
            }
        }

        Commands::SetVersion {
            version,
            docker_image,
            mandatory,
            deadline_block,
        } => {
            info!(
                "Setting required version: {} (mandatory: {})",
                version, mandatory
            );
            SudoAction::SetRequiredVersion {
                min_version: version.clone(),
                recommended_version: version,
                docker_image,
                mandatory,
                deadline_block,
                release_notes: None,
            }
        }

        Commands::ListChallenges => {
            let client = reqwest::Client::new();
            let rpc_url = format!("{}/rpc", args.rpc.trim_end_matches('/'));

            let response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getState",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await?;

            let result: serde_json::Value = response.json().await?;

            if let Some(error) = result.get("error") {
                eprintln!("RPC Error: {}", error);
                return Ok(());
            }

            if let Some(state) = result.get("result") {
                println!("=== Challenge Configs ===");
                if let Some(configs) = state.get("challenge_configs") {
                    if let Some(obj) = configs.as_object() {
                        if obj.is_empty() {
                            println!("No challenges registered.");
                        } else {
                            for (id, config) in obj {
                                println!("\nID: {}", id);
                                if let Some(name) = config.get("name") {
                                    println!("  Name: {}", name);
                                }
                                if let Some(image) = config.get("docker_image") {
                                    println!("  Docker: {}", image);
                                }
                                if let Some(mech) = config.get("mechanism_id") {
                                    println!("  Mechanism: {}", mech);
                                }
                                if let Some(weight) = config.get("emission_weight") {
                                    println!(
                                        "  Weight: {:.2}%",
                                        weight.as_f64().unwrap_or(0.0) * 100.0
                                    );
                                }
                            }
                        }
                    }
                }

                println!("\n=== Challenge Weights ===");
                if let Some(weights) = state.get("challenge_weights") {
                    if let Some(obj) = weights.as_object() {
                        if obj.is_empty() {
                            println!("No weight allocations set.");
                        } else {
                            for (id, alloc) in obj {
                                println!("\nChallenge: {}", id);
                                if let Some(mech) = alloc.get("mechanism_id") {
                                    println!("  Mechanism: {}", mech);
                                }
                                if let Some(ratio) = alloc.get("weight_ratio") {
                                    println!(
                                        "  Ratio: {:.2}%",
                                        ratio.as_f64().unwrap_or(0.0) * 100.0
                                    );
                                }
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        Commands::ListMechanisms => {
            let client = reqwest::Client::new();
            let rpc_url = format!("{}/rpc", args.rpc.trim_end_matches('/'));

            let response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getState",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await?;

            let result: serde_json::Value = response.json().await?;

            if let Some(error) = result.get("error") {
                eprintln!("RPC Error: {}", error);
                return Ok(());
            }

            if let Some(state) = result.get("result") {
                println!("=== Mechanism Configs ===");
                if let Some(configs) = state.get("mechanism_configs") {
                    if let Some(obj) = configs.as_object() {
                        if obj.is_empty() {
                            println!("No mechanism configs set (using defaults).");
                        } else {
                            for (id, config) in obj {
                                println!("\nMechanism: {}", id);
                                if let Some(burn) = config.get("base_burn_rate") {
                                    println!(
                                        "  Burn Rate: {:.2}%",
                                        burn.as_f64().unwrap_or(0.0) * 100.0
                                    );
                                }
                                if let Some(cap) = config.get("max_weight_cap") {
                                    println!(
                                        "  Max Cap: {:.2}%",
                                        cap.as_f64().unwrap_or(0.5) * 100.0
                                    );
                                }
                                if let Some(equal) = config.get("equal_distribution") {
                                    println!("  Equal Distribution: {}", equal);
                                }
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        Commands::AddValidator { hotkey, stake } => {
            let hk = Hotkey::from_hex(&hotkey).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
            let stake_raw = (stake * 1_000_000_000.0) as u64;
            let info = ValidatorInfo::new(hk, Stake::new(stake_raw));
            info!("Adding validator: {} with {} TAO", hotkey, stake);
            SudoAction::AddValidator { info }
        }

        Commands::RemoveValidator { hotkey } => {
            let hk = Hotkey::from_hex(&hotkey).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
            info!("Removing validator: {}", hotkey);
            SudoAction::RemoveValidator { hotkey: hk }
        }

        Commands::UpdateConfig {
            min_stake,
            threshold,
            block_time,
        } => {
            let mut config = NetworkConfig::default();
            if let Some(s) = min_stake {
                config.min_stake = Stake::new((s * 1_000_000_000.0) as u64);
            }
            if let Some(t) = threshold {
                config.consensus_threshold = t;
            }
            if let Some(bt) = block_time {
                config.block_time_ms = bt;
            }
            info!("Updating network configuration");
            SudoAction::UpdateConfig { config }
        }

        Commands::Pause { reason } => {
            info!("Pausing network: {}", reason);
            SudoAction::EmergencyPause { reason }
        }

        Commands::Resume => {
            info!("Resuming network");
            SudoAction::Resume
        }

        Commands::Status => {
            let client = reqwest::Client::new();
            let rpc_url = format!("{}/rpc", args.rpc.trim_end_matches('/'));

            println!("=== Network Status ===");
            println!("RPC: {}", args.rpc);

            let health_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "system_health",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await;

            match health_response {
                Ok(resp) => {
                    if let Ok(result) = resp.json::<serde_json::Value>().await {
                        if let Some(health) = result.get("result") {
                            println!("\nHealth:");
                            if let Some(peers) = health.get("peers") {
                                println!("  Peers: {}", peers);
                            }
                            if let Some(syncing) = health.get("isSyncing") {
                                println!("  Syncing: {}", syncing);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to RPC: {}", e);
                    return Ok(());
                }
            }

            let state_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getState",
                    "params": [],
                    "id": 2
                }))
                .send()
                .await?;

            let state_result: serde_json::Value = state_response.json().await?;

            if let Some(state) = state_result.get("result") {
                println!("\nChain State:");
                if let Some(block) = state.get("block_height") {
                    println!("  Block Height: {}", block);
                }
                if let Some(epoch) = state.get("epoch") {
                    println!("  Epoch: {}", epoch);
                }
                if let Some(validators) = state.get("validators") {
                    if let Some(obj) = validators.as_object() {
                        println!("  Validators: {}", obj.len());
                    }
                }
                if let Some(configs) = state.get("challenge_configs") {
                    if let Some(obj) = configs.as_object() {
                        println!("  Challenges: {}", obj.len());
                    }
                }
                if let Some(mechs) = state.get("mechanism_configs") {
                    if let Some(obj) = mechs.as_object() {
                        println!("  Mechanisms Configured: {}", obj.len());
                    }
                }
            }

            return Ok(());
        }
    };

    // Create signed messages for the sudo action
    info!("Creating signed sudo action...");
    let proposal_id = consensus.propose_sudo(action).await?;
    info!("Proposal created: {:?}", proposal_id);

    // Collect all messages to broadcast
    let mut messages_to_send: Vec<SignedNetworkMessage> = Vec::new();
    while let Ok(msg) = msg_rx.try_recv() {
        messages_to_send.push(msg);
    }

    if messages_to_send.is_empty() {
        eprintln!("No messages generated - action may have failed");
        return Ok(());
    }

    // Submit each message via RPC
    info!(
        "Submitting {} messages via RPC to {}...",
        messages_to_send.len(),
        args.rpc
    );
    let client = reqwest::Client::new();

    for msg in &messages_to_send {
        let serialized = bincode::serialize(&msg)?;
        let hex_encoded = hex::encode(&serialized);

        let rpc_url = if args.rpc.ends_with("/rpc") {
            args.rpc.clone()
        } else {
            format!("{}/rpc", args.rpc.trim_end_matches('/'))
        };

        let response = client
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "sudo_submit",
                "params": {
                    "signedMessage": hex_encoded
                },
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(error) = result.get("error") {
            eprintln!("RPC Error: {}", error);
            return Ok(());
        }

        if let Some(res) = result.get("result") {
            info!("Message submitted: {:?}", res);
        }
    }

    info!("Action submitted successfully via RPC!");
    Ok(())
}
