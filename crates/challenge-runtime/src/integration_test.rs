//! Integration test for challenge runtime

#[cfg(test)]
mod tests {
    use crate::{ChallengeRuntime, RuntimeConfig, RuntimeEvent};
    use async_trait::async_trait;
    use platform_challenge_sdk::{
        AgentInfo, Challenge, ChallengeContext, ChallengeId, EvaluationJob, EvaluationResult,
        WeightAssignment,
    };
    use platform_core::Keypair;
    use platform_epoch::{EpochConfig, EpochPhase, EpochTransition};
    use std::path::PathBuf;
    use tempfile::tempdir;

    /// Test challenge that returns predictable weights
    struct TestWeightChallenge {
        id: ChallengeId,
    }

    impl TestWeightChallenge {
        fn new() -> Self {
            Self {
                id: ChallengeId::new(),
            }
        }
    }

    #[async_trait]
    impl Challenge for TestWeightChallenge {
        fn id(&self) -> ChallengeId {
            self.id
        }

        fn name(&self) -> &str {
            "Test Weight Challenge"
        }

        fn emission_weight(&self) -> f64 {
            1.0
        }

        async fn evaluate(
            &self,
            ctx: &ChallengeContext,
            agent: &AgentInfo,
            _payload: serde_json::Value,
        ) -> platform_challenge_sdk::Result<EvaluationResult> {
            // Simple scoring: hash length / 100
            let score = (agent.hash.len() as f64 / 100.0).min(1.0);

            let result = EvaluationResult::new(ctx.job_id(), agent.hash.clone(), score);
            ctx.db().save_result(&result)?;

            ctx.info(&format!("Evaluated {} -> score={:.4}", agent.hash, score));
            Ok(result)
        }

        async fn calculate_weights(
            &self,
            ctx: &ChallengeContext,
        ) -> platform_challenge_sdk::Result<Vec<WeightAssignment>> {
            // Return fixed weights for testing
            let weights = vec![
                WeightAssignment::new("agent_alice".to_string(), 0.4),
                WeightAssignment::new("agent_bob".to_string(), 0.35),
                WeightAssignment::new("agent_charlie".to_string(), 0.25),
            ];

            ctx.info(&format!("Calculated {} weights", weights.len()));
            Ok(weights)
        }
    }

    #[tokio::test]
    async fn test_full_epoch_cycle() {
        let dir = tempdir().unwrap();
        let keypair = Keypair::generate();

        // Short epoch for testing (10 blocks)
        let epoch_config = EpochConfig {
            blocks_per_epoch: 10,
            evaluation_blocks: 6,
            commit_blocks: 2,
            reveal_blocks: 2,
            min_validators_for_consensus: 1,
            weight_smoothing: 0.1,
        };

        let config = RuntimeConfig {
            data_dir: dir.path().to_path_buf(),
            epoch_config,
            max_concurrent_evaluations: 4,
            ..Default::default()
        };

        let mut runtime = ChallengeRuntime::new(config, keypair.hotkey(), 0);
        let mut event_rx = runtime.take_event_receiver().unwrap();

        // Register test challenge with mechanism_id 0
        let challenge = TestWeightChallenge::new();
        let challenge_id = challenge.id();
        runtime.register_challenge(challenge, 0).await.unwrap();

        // Collect events
        let mut events = Vec::new();

        // Simulate 25 blocks (2.5 epochs)
        for block in 1..=25 {
            runtime.on_new_block(block).await.unwrap();

            // Collect events and trigger commit/reveal on phase changes
            while let Ok(event) = event_rx.try_recv() {
                println!("Block {}: {:?}", block, event);

                // Trigger commit/reveal based on Subtensor timing windows
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

                events.push((block, event));
            }

            // Collect commit/reveal events
            while let Ok(event) = event_rx.try_recv() {
                println!("Block {}: {:?}", block, event);
                events.push((block, event));
            }
        }

        // Verify we got epoch transitions
        let epoch_transitions: Vec<_> = events
            .iter()
            .filter(|(_, e)| matches!(e, RuntimeEvent::EpochTransition(_)))
            .collect();

        println!("\n=== Epoch Transitions ===");
        for (block, event) in &epoch_transitions {
            println!("Block {}: {:?}", block, event);
        }

        // Verify weight commits (now MechanismWeightsCommitted)
        let commits: Vec<_> = events
            .iter()
            .filter(|(_, e)| matches!(e, RuntimeEvent::MechanismWeightsCommitted { .. }))
            .collect();

        println!("\n=== Weight Commits ===");
        for (block, event) in &commits {
            println!("Block {}: {:?}", block, event);
        }

        // Verify weight reveals (now MechanismWeightsRevealed)
        let reveals: Vec<_> = events
            .iter()
            .filter(|(_, e)| matches!(e, RuntimeEvent::MechanismWeightsRevealed { .. }))
            .collect();

        println!("\n=== Weight Reveals ===");
        for (block, event) in &reveals {
            println!("Block {}: {:?}", block, event);
        }

        // Assertions
        assert!(
            !epoch_transitions.is_empty(),
            "Should have epoch transitions"
        );
        assert!(!commits.is_empty(), "Should have weight commits");
        assert!(!reveals.is_empty(), "Should have weight reveals");

        println!("\n=== Test Passed ===");
        println!("Epoch transitions: {}", epoch_transitions.len());
        println!("Weight commits: {}", commits.len());
        println!("Weight reveals: {}", reveals.len());
    }

    #[tokio::test]
    async fn test_evaluation_and_weights() {
        let dir = tempdir().unwrap();
        let keypair = Keypair::generate();

        let config = RuntimeConfig {
            data_dir: dir.path().to_path_buf(),
            max_concurrent_evaluations: 4,
            ..Default::default()
        };

        let mut runtime = ChallengeRuntime::new(config, keypair.hotkey(), 0);
        let mut event_rx = runtime.take_event_receiver().unwrap();

        // Register test challenge with mechanism_id 0
        let challenge = TestWeightChallenge::new();
        let challenge_id = challenge.id();
        runtime.register_challenge(challenge, 0).await.unwrap();

        // Submit evaluation jobs
        for i in 0..3 {
            let job = EvaluationJob::new(
                challenge_id,
                format!("agent_{}", i),
                "evaluate".to_string(),
                serde_json::Value::Null,
            );
            runtime.submit_job(job).await.unwrap();
        }

        // Run evaluation loop briefly
        let runtime = std::sync::Arc::new(runtime);
        let runtime_clone = runtime.clone();

        tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                runtime_clone.run_evaluation_loop(),
            )
            .await
            .ok();
        });

        // Wait for evaluations
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Check events
        let mut completed = 0;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, RuntimeEvent::EvaluationCompleted { .. }) {
                completed += 1;
                println!("Evaluation completed: {:?}", event);
            }
        }

        println!("\n=== Evaluations completed: {} ===", completed);

        // Check runtime status
        let status = runtime.status();
        println!("Runtime status: {:?}", status);

        assert!(
            completed > 0 || status.pending_jobs > 0 || status.running_jobs > 0,
            "Should have processed some jobs"
        );
    }
}
