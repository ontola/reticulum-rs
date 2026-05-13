//! 100-node LoRa-class line smoke (MeshSim + calibrated PHY knobs).

use reticulum_mesh_sim::lora_realistic_100_node_line_benchmark;

#[test]
fn lora_100_realistic_line_runs_and_exchanges_announces() {
    let ticks = 500u64;
    let report = lora_realistic_100_node_line_benchmark(ticks);

    assert_eq!(report.params.nodes, 100);
    assert!(report.stats.announces_sent > 0);
    assert!(
        report.stats.announces_received > 0,
        "some announces should be heard under calibrated LoRa load"
    );
}
