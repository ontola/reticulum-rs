//! Sharded Embassy executors: many `EmbeddedTransport` instances (announce-only line).

use std::time::Duration as StdDuration;

use reticulum_mesh_sim::embassy_mesh::{
    run_line_scale_harness, EmbassyLineScaleParams, MAX_NODES_PER_EMBASSY_SHARD,
};

#[test]
fn embassy_scale_line_32_nodes_finishes_and_sees_airtime() {
    let p = EmbassyLineScaleParams {
        nodes: 32,
        worker_threads: 4,
        spacing: 50.0,
        range: 60.0,
        announce_period_ms: 120,
        run_for: StdDuration::from_secs(3),
        channel_capacity: 64,
        collect_timeout: StdDuration::from_secs(90),
    };
    let report = run_line_scale_harness(&p).expect("scale harness");

    assert_eq!(report.node_stats.len(), 32);

    let mid = &report.node_stats[16];
    assert!(
        mid.interface_ingress_count > 0 || mid.synthetic_ingress_count > 0,
        "middle node should see some ingress after line chatter"
    );
}

/// Run manually: `cargo test -p reticulum-mesh-sim embassy_line_512_nodes -- --ignored --release`
#[test]
#[ignore = "slow / memory-heavy; run locally with --release"]
fn embassy_line_512_nodes_release_smoke() {
    let workers = 8usize;
    let nodes = MAX_NODES_PER_EMBASSY_SHARD * workers;
    let p = EmbassyLineScaleParams {
        nodes,
        worker_threads: workers,
        spacing: 50.0,
        range: 60.0,
        announce_period_ms: 200,
        run_for: StdDuration::from_secs(5),
        channel_capacity: 64,
        collect_timeout: StdDuration::from_secs(300),
    };
    let report = run_line_scale_harness(&p).expect("scale harness");
    assert_eq!(report.node_stats.len(), nodes);
    let last = report.node_stats.last().expect("last node");
    assert!(last.announce_count > 0 || last.interface_ingress_count > 0);
}
