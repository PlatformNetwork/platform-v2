//! End-to-End Integration Tests for Mini-Chain
//!
//! These tests verify the complete system works together.

use platform_challenge_runtime::{ChallengeRuntime, RuntimeConfig, RuntimeEvent};
use platform_challenge_sdk::{Challenge, EvaluationJob, SimpleTestChallenge, WeightAssignment};
use platform_core::{ChainState, Keypair, NetworkConfig, Stake, ValidatorInfo};
use platform_epoch::{EpochConfig, EpochPhase, EpochTransition};
use std::sync::Arc;
use tempfile::tempdir;

/// Test complete epoch cycle with challenge evaluation
#[tokio::test]
async fn test_e2e_epoch_cycle() {
    let dir = tempdir().unwrap();
    let keypair = Keypair::generate();

    // Short epochs for testing
    let epoch_config = EpochConfig {
        blocks_per_epoch: 20,
        evaluation_blocks: 12,
        commit_blocks: 4,
        reveal_blocks: 4,
        min_validators_for_consensus: 1,
        weight_smoothing: 0.1,
    };

    let config = RuntimeConfig {
        data_dir: dir.path().to_path_buf(),
        epoch_config,
        max_concurrent_evaluations: 4,
        ..Default::default()
    };

    // Create runtime
    let mut runtime = ChallengeRuntime::new(config, keypair.hotkey(), 0);
    let mut event_rx = runtime.take_event_receiver().unwrap();

    // Register challenge
    let challenge = SimpleTestChallenge::new("E2E Test Challenge", 1.0);
    let challenge_id = challenge.id();
    runtime.register_challenge(challenge, 0).await.unwrap();

    // Submit some evaluation jobs
    for i in 0..5 {
        let job = EvaluationJob::new(
            challenge_id,
            format!("agent_e2e_{}", i),
            "evaluate".to_string(),
            serde_json::json!({"bonus": 0.1}),
        );
        runtime.submit_job(job).await.unwrap();
    }

    // Spawn evaluation loop with timeout
    let runtime = Arc::new(runtime);
    let runtime_for_eval = runtime.clone();
    tokio::spawn(async move {
        // Timeout after 5 seconds to prevent infinite loop
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            runtime_for_eval.run_evaluation_loop(),
        )
        .await;
    });

    // Collect events
    let mut events = Vec::new();
    let mut evaluations_completed = 0;
    let mut weights_committed = 0;
    let mut weights_revealed = 0;
    let mut epochs_completed = 0;

    // Simulate 50 blocks (2.5 epochs)
    for block in 1..=50 {
        runtime.on_new_block(block).await.unwrap();

        // Small delay to allow evaluation loop to process
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Collect events and trigger commit/reveal on Subtensor timing windows
        while let Ok(event) = event_rx.try_recv() {
            if let RuntimeEvent::EpochTransition(ref transition) = event {
                match transition {
                    EpochTransition::PhaseChange {
                        epoch,
                        new_phase: EpochPhase::Commit,
                        ..
                    } => {
                        runtime.commit_weights(*epoch).await.unwrap();
                    }
                    EpochTransition::PhaseChange {
                        epoch,
                        new_phase: EpochPhase::Reveal,
                        ..
                    } => {
                        runtime.reveal_weights(*epoch).await.unwrap();
                    }
                    _ => {}
                }
            }

            match &event {
                RuntimeEvent::EvaluationCompleted { .. } => evaluations_completed += 1,
                RuntimeEvent::MechanismWeightsCommitted { .. } => weights_committed += 1,
                RuntimeEvent::MechanismWeightsRevealed { .. } => weights_revealed += 1,
                RuntimeEvent::EpochTransition(t) => {
                    if matches!(t, EpochTransition::NewEpoch { .. }) {
                        epochs_completed += 1;
                    }
                }
                _ => {}
            }
            events.push((block, event));
        }

        // Collect commit/reveal events
        while let Ok(event) = event_rx.try_recv() {
            match &event {
                RuntimeEvent::MechanismWeightsCommitted { .. } => weights_committed += 1,
                RuntimeEvent::MechanismWeightsRevealed { .. } => weights_revealed += 1,
                _ => {}
            }
            events.push((block, event));
        }
    }

    // Verify results
    println!("=== E2E Test Results ===");
    println!("Evaluations completed: {}", evaluations_completed);
    println!("Weights committed: {}", weights_committed);
    println!("Weights revealed: {}", weights_revealed);
    println!("Epochs completed: {}", epochs_completed);

    assert!(
        evaluations_completed > 0,
        "Should have completed some evaluations"
    );
    assert!(weights_committed > 0, "Should have committed weights");
    assert!(weights_revealed > 0, "Should have revealed weights");
    assert!(
        epochs_completed >= 2,
        "Should have completed at least 2 epochs"
    );
}

/// Test multi-validator consensus simulation
#[tokio::test]
async fn test_e2e_multi_validator_state() {
    use parking_lot::RwLock;

    // Create 8 validators
    let validators: Vec<_> = (0..8).map(|_| Keypair::generate()).collect();

    // Create shared state
    let sudo = validators[0].hotkey();
    let state = Arc::new(RwLock::new(ChainState::new(sudo, NetworkConfig::default())));

    // Add all validators
    for (i, kp) in validators.iter().enumerate() {
        let stake = Stake::new((100 + i as u64) * 1_000_000_000);
        let info = ValidatorInfo::new(kp.hotkey(), stake);
        state.write().add_validator(info).unwrap();
    }

    // Verify state
    let s = state.read();
    assert_eq!(s.validators.len(), 8);

    // Calculate consensus threshold (50% = 4 validators)
    let threshold = s.consensus_threshold();
    assert_eq!(threshold, 4);

    // Verify total stake
    let total_stake: u64 = s.validators.values().map(|v| v.stake.0).sum();
    assert!(total_stake > 800 * 1_000_000_000);

    println!("=== Multi-Validator State ===");
    println!("Validators: {}", s.validators.len());
    println!("Consensus threshold: {}", threshold);
    println!("Total stake: {} TAO", total_stake / 1_000_000_000);
}

/// Test weight calculation and normalization
#[tokio::test]
async fn test_e2e_weight_calculation() {
    use platform_challenge_sdk::weights::{normalize_weights, scores_to_weights, smooth_weights};

    // Simulate evaluation scores
    let scores = vec![
        ("agent_1".to_string(), 0.9),
        ("agent_2".to_string(), 0.7),
        ("agent_3".to_string(), 0.5),
        ("agent_4".to_string(), 0.3),
        ("agent_5".to_string(), 0.1),
    ];

    // Convert to weights
    let weights = scores_to_weights(&scores, 1.0);

    // Normalize
    let normalized = normalize_weights(weights);

    // Verify sum is ~1.0
    let sum: f64 = normalized.iter().map(|w| w.weight).sum();
    assert!((sum - 1.0).abs() < 0.01, "Weights should sum to 1.0");

    // Apply smoothing
    let smoothed = smooth_weights(normalized.clone(), 0.2);

    // Verify smoothed weights are less extreme
    assert!(smoothed[0].weight < normalized[0].weight + 0.1);

    println!("=== Weight Calculation ===");
    for (i, (n, s)) in normalized.iter().zip(smoothed.iter()).enumerate() {
        println!(
            "Agent {}: normalized={:.4}, smoothed={:.4}",
            i + 1,
            n.weight,
            s.weight
        );
    }
}

/// Test challenge database isolation
#[tokio::test]
async fn test_e2e_challenge_db_isolation() {
    use platform_challenge_sdk::{AgentInfo, ChallengeDatabase, ChallengeId, EvaluationResult};

    let dir = tempdir().unwrap();

    // Create two challenges with separate databases
    let challenge1_id = ChallengeId::new();
    let challenge2_id = ChallengeId::new();

    let db1 = ChallengeDatabase::open(dir.path(), challenge1_id).unwrap();
    let db2 = ChallengeDatabase::open(dir.path(), challenge2_id).unwrap();

    // Save data to db1
    let agent1 = AgentInfo::new("agent_in_db1".to_string());
    db1.save_agent(&agent1).unwrap();

    let result1 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent_in_db1".to_string(), 0.8);
    db1.save_result(&result1).unwrap();

    // Save different data to db2
    let agent2 = AgentInfo::new("agent_in_db2".to_string());
    db2.save_agent(&agent2).unwrap();

    let result2 = EvaluationResult::new(uuid::Uuid::new_v4(), "agent_in_db2".to_string(), 0.6);
    db2.save_result(&result2).unwrap();

    // Verify isolation
    let db1_results = db1.get_latest_results().unwrap();
    let db2_results = db2.get_latest_results().unwrap();

    assert_eq!(db1_results.len(), 1);
    assert_eq!(db2_results.len(), 1);
    assert_eq!(db1_results[0].agent_hash, "agent_in_db1");
    assert_eq!(db2_results[0].agent_hash, "agent_in_db2");

    println!("=== Database Isolation ===");
    println!("Challenge 1 DB: {} results", db1_results.len());
    println!("Challenge 2 DB: {} results", db2_results.len());
    println!("Databases are properly isolated!");
}
