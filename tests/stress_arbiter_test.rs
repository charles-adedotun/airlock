#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![allow(clippy::uninlined_format_args)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use airlock::arbiter::{ChannelArbiter, ConflictError, ConflictPolicy};
use airlock::ingest::UpstreamHub;
use futures_util::future::join_all;
use tokio::sync::Barrier;

/// Test 1: 100 concurrent tokio tasks racing to acquire different stream IDs
/// through `ChannelArbiter::acquire_guard` with `Preempt` and `RejectIfActive`.
/// Verifies mathematically and via atomic assertions that `active_subscribers()`
/// and `active_stream()` strictly maintain the single-upstream invariant
/// (<= 1 stream active) across all interleavings.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_100_concurrent_channel_zapping_storm() {
    let start_total = Instant::now();
    println!("\n=== [TEST 1] test_stress_100_concurrent_channel_zapping_storm ===");

    // -------------------------------------------------------------
    // Phase A: ConflictPolicy::Preempt
    // -------------------------------------------------------------
    println!("--- Phase A: ConflictPolicy::Preempt (100 concurrent workers, 5,000 acquires) ---");
    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::Preempt));
    assert_eq!(arbiter.policy(), ConflictPolicy::Preempt);

    let stop_monitor_a = Arc::new(AtomicBool::new(false));
    let monitor_stop_clone_a = Arc::clone(&stop_monitor_a);
    let arbiter_mon_a = Arc::clone(&arbiter);
    let monitor_checks_a = Arc::new(AtomicUsize::new(0));
    let checks_clone_a = Arc::clone(&monitor_checks_a);

    let monitor_handle_a = tokio::spawn(async move {
        let mut max_observed_subs = 0;
        while !monitor_stop_clone_a.load(Ordering::Relaxed) {
            let subs = arbiter_mon_a.active_subscribers();
            let stream = arbiter_mon_a.active_stream();

            // Mathematical Invariant 1: Single-upstream active stream consistency
            if subs > 0 {
                assert!(
                    stream.is_some(),
                    "INVARIANT VIOLATION: active_subscribers={subs} but active_stream is None!"
                );
            }

            // Mathematical Invariant 2: At most 1 active stream at any time
            // active_stream() returns Option<String>, fundamentally bounded to <= 1.

            // Mathematical Invariant 3: Upper bound on active subscribers
            assert!(
                subs <= 100,
                "INVARIANT VIOLATION: active_subscribers={subs} exceeded total concurrency (100)!"
            );

            if subs > max_observed_subs {
                max_observed_subs = subs;
            }
            checks_clone_a.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
        max_observed_subs
    });

    const CONCURRENCY_A: usize = 100;
    const OPS_PER_WORKER_A: usize = 50;
    let barrier_a = Arc::new(Barrier::new(CONCURRENCY_A + 1));
    let mut handles_a = Vec::with_capacity(CONCURRENCY_A);
    let granted_a = Arc::new(AtomicUsize::new(0));

    let phase_a_start = Instant::now();
    for task_id in 0..CONCURRENCY_A {
        let arb = Arc::clone(&arbiter);
        let bar = Arc::clone(&barrier_a);
        let granted_cnt = Arc::clone(&granted_a);

        handles_a.push(tokio::spawn(async move {
            bar.wait().await;
            for iter in 0..OPS_PER_WORKER_A {
                let target_stream = format!("ch_zap_{}", (task_id + iter) % 16);
                let (grant, guard) = arb
                    .acquire_guard(&target_stream, false)
                    .expect("Preempt policy must unconditionally grant access");

                assert_eq!(grant.stream_id(), target_stream.as_str());
                granted_cnt.fetch_add(1, Ordering::Relaxed);

                // Simulated consumption
                tokio::task::yield_now().await;
                drop(guard);
            }
        }));
    }

    barrier_a.wait().await;
    join_all(handles_a).await;

    stop_monitor_a.store(true, Ordering::Relaxed);
    let max_subs_a = monitor_handle_a.await.expect("monitor A join failed");
    let phase_a_dur = phase_a_start.elapsed();

    let total_ops_a = granted_a.load(Ordering::SeqCst);
    assert_eq!(
        total_ops_a,
        CONCURRENCY_A * OPS_PER_WORKER_A,
        "All Phase A acquisitions must succeed"
    );
    assert_eq!(
        arbiter.active_subscribers(),
        0,
        "All guards dropped in Phase A; active_subscribers must be 0"
    );

    println!(
        "Phase A completed in {:?} (ops: {}, throughput: {:.1} ops/sec, max concurrent subs: {}, invariant checks: {})",
        phase_a_dur,
        total_ops_a,
        (total_ops_a as f64) / phase_a_dur.as_secs_f64(),
        max_subs_a,
        monitor_checks_a.load(Ordering::Relaxed)
    );

    // -------------------------------------------------------------
    // Phase B: ConflictPolicy::RejectIfActive
    // -------------------------------------------------------------
    println!(
        "--- Phase B: ConflictPolicy::RejectIfActive (100 concurrent workers, 5,000 requests) ---"
    );
    arbiter.reset();
    arbiter.set_policy(ConflictPolicy::RejectIfActive);
    assert_eq!(arbiter.policy(), ConflictPolicy::RejectIfActive);
    assert_eq!(arbiter.active_stream(), None);
    assert_eq!(arbiter.active_subscribers(), 0);

    let stop_monitor_b = Arc::new(AtomicBool::new(false));
    let monitor_stop_clone_b = Arc::clone(&stop_monitor_b);
    let arbiter_mon_b = Arc::clone(&arbiter);
    let monitor_checks_b = Arc::new(AtomicUsize::new(0));
    let checks_clone_b = Arc::clone(&monitor_checks_b);

    let monitor_handle_b = tokio::spawn(async move {
        let mut max_observed_subs = 0;
        while !monitor_stop_clone_b.load(Ordering::Relaxed) {
            let subs = arbiter_mon_b.active_subscribers();
            let stream = arbiter_mon_b.active_stream();

            if subs > 0 {
                assert!(
                    stream.is_some(),
                    "INVARIANT VIOLATION: active_subscribers={subs} but active_stream is None!"
                );
            }
            assert!(
                subs <= 100,
                "INVARIANT VIOLATION: active_subscribers={subs} exceeded total concurrency (100)!"
            );

            if subs > max_observed_subs {
                max_observed_subs = subs;
            }
            checks_clone_b.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
        max_observed_subs
    });

    const CONCURRENCY_B: usize = 100;
    const OPS_PER_WORKER_B: usize = 50;
    let barrier_b = Arc::new(Barrier::new(CONCURRENCY_B + 1));
    let mut handles_b = Vec::with_capacity(CONCURRENCY_B);
    let granted_b = Arc::new(AtomicUsize::new(0));
    let conflicted_b = Arc::new(AtomicUsize::new(0));

    let phase_b_start = Instant::now();
    for task_id in 0..CONCURRENCY_B {
        let arb = Arc::clone(&arbiter);
        let bar = Arc::clone(&barrier_b);
        let granted_cnt = Arc::clone(&granted_b);
        let conflicted_cnt = Arc::clone(&conflicted_b);

        handles_b.push(tokio::spawn(async move {
            bar.wait().await;
            for iter in 0..OPS_PER_WORKER_B {
                let target_stream = format!("ch_reject_{}", (task_id + iter) % 8);
                // 1 in 8 requests uses force=true to preempt
                let force = (task_id + iter) % 8 == 0;

                match arb.acquire_guard(&target_stream, force) {
                    Ok((grant, guard)) => {
                        assert_eq!(grant.stream_id(), target_stream.as_str());
                        granted_cnt.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                        drop(guard);
                    }
                    Err(ConflictError::StreamInUse {
                        active_stream_id,
                        active_subscribers,
                        ..
                    }) => {
                        assert!(!force, "force=true must never conflict");
                        assert!(active_subscribers > 0);
                        assert_ne!(active_stream_id, target_stream);
                        conflicted_cnt.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                }
            }
        }));
    }

    barrier_b.wait().await;
    join_all(handles_b).await;

    stop_monitor_b.store(true, Ordering::Relaxed);
    let max_subs_b = monitor_handle_b.await.expect("monitor B join failed");
    let phase_b_dur = phase_b_start.elapsed();

    let total_granted_b = granted_b.load(Ordering::SeqCst);
    let total_conflicted_b = conflicted_b.load(Ordering::SeqCst);
    let total_ops_b = total_granted_b + total_conflicted_b;

    assert_eq!(
        total_ops_b,
        CONCURRENCY_B * OPS_PER_WORKER_B,
        "Total operations must equal requests count"
    );
    assert!(total_granted_b > 0, "Must have granted requests in Phase B");
    assert!(
        total_conflicted_b > 0,
        "Must have conflicted requests in Phase B"
    );
    assert_eq!(
        arbiter.active_subscribers(),
        0,
        "All guards dropped in Phase B; active_subscribers must be 0"
    );

    println!(
        "Phase B completed in {:?} (ops: {}, granted: {}, conflicted: {}, throughput: {:.1} ops/sec, max concurrent subs: {}, invariant checks: {})",
        phase_b_dur,
        total_ops_b,
        total_granted_b,
        total_conflicted_b,
        (total_ops_b as f64) / phase_b_dur.as_secs_f64(),
        max_subs_b,
        monitor_checks_b.load(Ordering::Relaxed)
    );

    // Final state restoration
    if let Some(stream) = arbiter.active_stream() {
        arbiter.release_stream(&stream);
    }
    assert_eq!(arbiter.active_stream(), None);
    assert_eq!(arbiter.active_subscribers(), 0);

    let total_duration = start_total.elapsed();
    println!(
        "=== [TEST 1 PASSED] 10,000 total acquisitions/contention tests across 100 tasks in {:?} ===",
        total_duration
    );
}

/// Test 2: Spin up 200 concurrent tasks in parallel, each acquiring guards for the same stream,
/// immediately doing simulated work, and dropping the guard. Execute 5,000 total acquisitions.
/// Verify atomic subscriber counter never drifts, never underflows, and returns to 0 when idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_high_frequency_guard_churn() {
    let start_total = Instant::now();
    println!("\n=== [TEST 2] test_stress_high_frequency_guard_churn ===");

    const CONCURRENCY: usize = 200;
    const ACQUISITIONS_PER_TASK: usize = 25;
    const TOTAL_ACQUISITIONS: usize = CONCURRENCY * ACQUISITIONS_PER_TASK; // 5,000 acquisitions
    const TARGET_STREAM: &str = "high_churn_shared_stream";

    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));

    let stop_monitor = Arc::new(AtomicBool::new(false));
    let stop_monitor_clone = Arc::clone(&stop_monitor);
    let arb_mon = Arc::clone(&arbiter);
    let monitor_samples = Arc::new(AtomicUsize::new(0));
    let samples_clone = Arc::clone(&monitor_samples);

    let monitor_handle = tokio::spawn(async move {
        let mut max_subs = 0;
        while !stop_monitor_clone.load(Ordering::Relaxed) {
            let subs = arb_mon.active_subscribers();
            if subs > max_subs {
                max_subs = subs;
            }
            assert!(
                subs <= CONCURRENCY,
                "INVARIANT VIOLATION: active_subscribers={subs} exceeded total concurrency ({CONCURRENCY})!"
            );
            samples_clone.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
        max_subs
    });

    let barrier = Arc::new(Barrier::new(CONCURRENCY + 1));
    let mut handles = Vec::with_capacity(CONCURRENCY);
    let completed_acquisitions = Arc::new(AtomicUsize::new(0));

    let churn_start = Instant::now();
    for _ in 0..CONCURRENCY {
        let arb = Arc::clone(&arbiter);
        let bar = Arc::clone(&barrier);
        let completed = Arc::clone(&completed_acquisitions);

        handles.push(tokio::spawn(async move {
            bar.wait().await;
            for _ in 0..ACQUISITIONS_PER_TASK {
                let (grant, guard) = arb
                    .acquire_guard(TARGET_STREAM, false)
                    .expect("Acquisition on the same active stream must always succeed");

                assert_eq!(grant.stream_id(), TARGET_STREAM);
                assert!(!grant.is_preemption());

                // Invariant: while guard is held, subscribers must be at least 1 and at most CONCURRENCY
                let active_subs = arb.active_subscribers();
                assert!(
                    active_subs >= 1,
                    "INVARIANT VIOLATION: active_subscribers underflowed to 0 while guard is held!"
                );
                assert!(
                    active_subs <= CONCURRENCY,
                    "INVARIANT VIOLATION: active_subscribers={active_subs} exceeded max concurrency!"
                );

                // Simulated payload consumption
                tokio::task::yield_now().await;

                // Explicit drop of the RAII guard triggers release_subscriber
                drop(guard);
                completed.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    barrier.wait().await;
    join_all(handles).await;

    stop_monitor.store(true, Ordering::Relaxed);
    let max_observed_subs = monitor_handle.await.expect("monitor join failed");
    let churn_dur = churn_start.elapsed();

    let total_done = completed_acquisitions.load(Ordering::SeqCst);
    assert_eq!(
        total_done, TOTAL_ACQUISITIONS,
        "Exactly 5,000 acquisitions must be executed"
    );

    // Invariant: Atomic subscriber counter must strictly return to 0 when idle
    let idle_subscribers = arbiter.active_subscribers();
    assert_eq!(
        idle_subscribers, 0,
        "CRITICAL INVARIANT VIOLATION: Subscriber counter drifted to {idle_subscribers} instead of 0!"
    );
    assert!(
        !arbiter.is_in_use(),
        "Arbiter must not report in_use when subscribers == 0"
    );
    assert_eq!(
        arbiter.active_stream().as_deref(),
        Some(TARGET_STREAM),
        "Active stream should retain last tuned channel until released"
    );

    arbiter.release_stream(TARGET_STREAM);
    assert_eq!(arbiter.active_stream(), None);
    assert_eq!(arbiter.active_subscribers(), 0);

    println!(
        "Churn completed in {:?} (acquisitions: {}, concurrency: {}, throughput: {:.1} ops/sec, peak concurrent subscribers: {}, invariant checks: {})",
        churn_dur,
        total_done,
        CONCURRENCY,
        (total_done as f64) / churn_dur.as_secs_f64(),
        max_observed_subs,
        monitor_samples.load(Ordering::Relaxed)
    );
    println!(
        "=== [TEST 2 PASSED] 5,000 acquisitions across 200 tasks in {:?} ===",
        start_total.elapsed()
    );
}

/// Test 3: Use `UpstreamHub` with rapid `switch_stream(id)` calls from 50 worker tasks.
/// Verify `active_stream()` is always consistent, single-upstream invariant is never broken,
/// and `release()` restores state cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_upstream_hub_switch_race() {
    let start_total = Instant::now();
    println!("\n=== [TEST 3] test_stress_upstream_hub_switch_race ===");

    // Micro-cooldown of 100 microseconds to exercise real cooldown timing barrier
    let hub = Arc::new(UpstreamHub::new(Duration::from_micros(100)));
    assert_eq!(hub.active_count(), 0);
    assert_eq!(hub.active_stream().await, None);

    const WORKERS: usize = 50;
    const SWITCHES_PER_WORKER: usize = 20;
    const TOTAL_SWITCHES: usize = WORKERS * SWITCHES_PER_WORKER; // 1,000 switches

    let stop_monitor = Arc::new(AtomicBool::new(false));
    let stop_monitor_clone = Arc::clone(&stop_monitor);
    let hub_mon = Arc::clone(&hub);
    let monitor_checks = Arc::new(AtomicUsize::new(0));
    let checks_clone = Arc::clone(&monitor_checks);

    let monitor_handle = tokio::spawn(async move {
        let mut max_observed_connections = 0;
        while !stop_monitor_clone.load(Ordering::Relaxed) {
            let active = hub_mon.active_count();
            if active > max_observed_connections {
                max_observed_connections = active;
            }
            assert!(
                active <= 1,
                "CRITICAL INVARIANT VIOLATION: UpstreamHub active_count() was {active} (> 1)!"
            );
            checks_clone.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
        max_observed_connections
    });

    let barrier = Arc::new(Barrier::new(WORKERS + 1));
    let mut handles = Vec::with_capacity(WORKERS);
    let successful_switches = Arc::new(AtomicUsize::new(0));

    let race_start = Instant::now();
    for task_id in 0..WORKERS {
        let hub_worker = Arc::clone(&hub);
        let bar = Arc::clone(&barrier);
        let switch_cnt = Arc::clone(&successful_switches);

        handles.push(tokio::spawn(async move {
            bar.wait().await;
            for iter in 0..SWITCHES_PER_WORKER {
                let target_stream = format!("hub_stream_{}", (task_id * 7 + iter) % 10);
                let conn = hub_worker
                    .switch_stream(&target_stream)
                    .await
                    .expect("switch_stream must succeed");

                // Invariant: connection counter must be exactly 1
                assert_eq!(
                    conn.load(Ordering::SeqCst),
                    1,
                    "Assigned connection counter must be 1"
                );
                assert_eq!(hub_worker.active_count(), 1, "Hub active_count must be 1");

                // Consistency: active_stream must be Some and valid while active_count == 1
                let current_stream = hub_worker.active_stream().await;
                assert!(
                    current_stream.is_some(),
                    "active_stream() must be Some while active_count == 1"
                );
                if let Some(ref st) = current_stream {
                    assert!(
                        st.starts_with("hub_stream_"),
                        "active_stream() contained invalid stream ID: {st}"
                    );
                }

                switch_cnt.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }));
    }

    barrier.wait().await;
    join_all(handles).await;

    stop_monitor.store(true, Ordering::Relaxed);
    let max_connections = monitor_handle.await.expect("monitor join failed");
    let race_dur = race_start.elapsed();

    let total_switches_done = successful_switches.load(Ordering::SeqCst);
    assert_eq!(
        total_switches_done, TOTAL_SWITCHES,
        "All 1,000 switches must complete successfully"
    );
    assert_eq!(
        max_connections, 1,
        "Invariant: max concurrent upstream connections must strictly be 1"
    );
    assert_eq!(hub.active_count(), 1);

    // Verify release() restores state cleanly
    let active_id = hub
        .active_stream()
        .await
        .expect("Must have an active stream after switches");
    hub.release(&active_id).await;

    assert_eq!(
        hub.active_count(),
        0,
        "active_count() must be 0 after clean release"
    );
    assert_eq!(
        hub.active_stream().await,
        None,
        "active_stream() must be None after clean release"
    );

    println!(
        "Switch race completed in {:?} (switches: {}, concurrency: {}, throughput: {:.1} switches/sec, max concurrent connections: {}, invariant checks: {})",
        race_dur,
        total_switches_done,
        WORKERS,
        (total_switches_done as f64) / race_dur.as_secs_f64(),
        max_connections,
        monitor_checks.load(Ordering::Relaxed)
    );
    println!(
        "=== [TEST 3 PASSED] 1,000 switches across 50 tasks in {:?} ===",
        start_total.elapsed()
    );
}

/// Test 4: Hammer `ChannelArbiter` with 1,000 concurrent acquire requests
/// with mixed `force=true` and `force=false`.
/// Verify that all requests are cleanly resolved into either Granted or Conflict
/// without deadlocks or race conditions.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_arbiter_concurrent_preemption_matrix() {
    let start_total = Instant::now();
    println!("\n=== [TEST 4] test_stress_arbiter_concurrent_preemption_matrix ===");

    let arbiter = Arc::new(ChannelArbiter::new(ConflictPolicy::RejectIfActive));

    // Prime with initial stream
    let (init_grant, init_guard) = arbiter
        .acquire_guard("prime_stream_alpha", false)
        .expect("Prime stream acquire must succeed");
    assert_eq!(init_grant.stream_id(), "prime_stream_alpha");
    assert_eq!(arbiter.active_subscribers(), 1);
    assert_eq!(
        arbiter.active_stream().as_deref(),
        Some("prime_stream_alpha")
    );

    const CONCURRENCY: usize = 1000;
    let barrier = Arc::new(Barrier::new(CONCURRENCY + 1));
    let mut handles = Vec::with_capacity(CONCURRENCY);

    let granted_counter = Arc::new(AtomicUsize::new(0));
    let conflict_counter = Arc::new(AtomicUsize::new(0));
    let force_granted_counter = Arc::new(AtomicUsize::new(0));
    let unforced_granted_counter = Arc::new(AtomicUsize::new(0));

    let matrix_start = Instant::now();
    for task_id in 0..CONCURRENCY {
        let arb = Arc::clone(&arbiter);
        let bar = Arc::clone(&barrier);
        let granted_cnt = Arc::clone(&granted_counter);
        let conflict_cnt = Arc::clone(&conflict_counter);
        let force_granted_cnt = Arc::clone(&force_granted_counter);
        let unforced_granted_cnt = Arc::clone(&unforced_granted_counter);

        // Mix force: task_id % 3 == 0 (334 with force=true, 666 with force=false)
        let force = task_id % 3 == 0;
        let target_stream = format!("matrix_ch_{}", task_id % 20);

        handles.push(tokio::spawn(async move {
            bar.wait().await;

            match arb.acquire_guard(&target_stream, force) {
                Ok((grant, guard)) => {
                    assert_eq!(grant.stream_id(), target_stream.as_str());
                    granted_cnt.fetch_add(1, Ordering::Relaxed);
                    if force {
                        force_granted_cnt.fetch_add(1, Ordering::Relaxed);
                    } else {
                        unforced_granted_cnt.fetch_add(1, Ordering::Relaxed);
                    }
                    tokio::task::yield_now().await;
                    drop(guard);
                }
                Err(ConflictError::StreamInUse {
                    active_stream_id,
                    active_subscribers,
                    ..
                }) => {
                    // Critical invariant assertions on Conflict
                    assert!(
                        !force,
                        "CRITICAL: force=true was rejected with StreamInUse!"
                    );
                    assert!(
                        active_subscribers > 0,
                        "CRITICAL: Conflict returned with 0 active subscribers!"
                    );
                    assert_ne!(
                        active_stream_id, target_stream,
                        "CRITICAL: Conflict returned for identical stream ID!"
                    );
                    conflict_cnt.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    // Release prime guard so it also participates in the race
    drop(init_guard);

    // Fire all 1,000 tasks at the exact same instant
    barrier.wait().await;
    join_all(handles).await;

    let matrix_dur = matrix_start.elapsed();

    let granted = granted_counter.load(Ordering::SeqCst);
    let conflicted = conflict_counter.load(Ordering::SeqCst);
    let force_granted = force_granted_counter.load(Ordering::SeqCst);
    let unforced_granted = unforced_granted_counter.load(Ordering::SeqCst);

    println!(
        "Matrix completed in {:?} (total requests: {}, granted: {}, conflicted: {}, force_granted: {}, unforced_granted: {}, throughput: {:.1} req/sec)",
        matrix_dur,
        CONCURRENCY,
        granted,
        conflicted,
        force_granted,
        unforced_granted,
        (CONCURRENCY as f64) / matrix_dur.as_secs_f64()
    );

    // Assert that every request resolved cleanly into either Granted or Conflict
    assert_eq!(
        granted + conflicted,
        CONCURRENCY,
        "Every request must cleanly resolve to either Granted or Conflict"
    );

    // All force=true requests (1000 / 3 + 1 = 334) must be granted unconditionally
    let expected_force_requests = (0..CONCURRENCY).filter(|i| i % 3 == 0).count();
    assert_eq!(
        force_granted, expected_force_requests,
        "Every single force=true request must be granted"
    );

    assert!(
        conflicted > 0,
        "Contention matrix must produce conflicts for unforced competing requests"
    );
    assert!(
        unforced_granted > 0,
        "Contention matrix must produce some unforced grants (same-stream fan-out / idle handover)"
    );

    // Invariant: all guards have dropped, so active subscribers must return strictly to 0
    let final_subscribers = arbiter.active_subscribers();
    assert_eq!(
        final_subscribers, 0,
        "All guards dropped; active_subscribers must be 0, found: {final_subscribers}"
    );

    // State reset cleanly
    arbiter.reset();
    assert_eq!(arbiter.active_stream(), None);
    assert_eq!(arbiter.active_subscribers(), 0);

    println!(
        "=== [TEST 4 PASSED] 1,000 concurrent acquire requests resolved in {:?} ===",
        start_total.elapsed()
    );
}
