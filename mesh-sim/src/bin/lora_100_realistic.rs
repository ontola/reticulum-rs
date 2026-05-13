//! 100-node LoRa-class line: bitrate-limited medium, staggered announces, short MAC airtime debit.
//!
//! Uses [`MeshSim`] (toy routing); PHY/cadence follow the calibrated sweep in `lora_sweep`.
//! Prefer `--release` for faster runs.
//!
//! ```text
//! cargo run -p reticulum-mesh-sim --release --bin lora_100_realistic -- 2000
//! ```

fn main() {
    let ticks: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1200);

    let report = reticulum_mesh_sim::lora_realistic_100_node_line_benchmark(ticks);
    let p = &report.params;
    let s = &report.stats;
    let m = &report.stability;

    println!("LoRa-class realistic line (MeshSim), N=100");
    println!(
        "  PHY: {} bit/s, tick={} µs, on_air={} B/debit, stagger_announces",
        reticulum_mesh_sim::LORA_CLASS_BITRATE_BPS,
        p.tick_duration_us,
        reticulum_mesh_sim::LORA_CLASS_ON_AIR_BYTES
    );
    println!(
        "  topo: spacing={} m, range={} m, announce_interval={} ticks (~{:.1} s/node)",
        p.spacing,
        p.radio_range,
        p.bandwidth.announce_interval,
        p.bandwidth.announce_interval as f64 * p.tick_duration_us as f64 / 1_000_000.0
    );
    println!("  run: ticks={ticks}");
    println!();
    println!(
        "traffic: announces_sent={} announces_recv={} air_tx_ok={} air_tx_attempts={}",
        s.announces_sent, s.announces_received, s.air_tx_ok, s.air_tx_attempts
    );
    println!(
        "drops: total={} throughput_limited={} air_queue_full={} inbox_full={}",
        s.dropped_total(),
        s.dropped_throughput_limited,
        s.dropped_air_queue_full,
        s.dropped_inbox_full
    );
    println!("queues: max_air={} max_inbox={}", s.max_air_queue_depth, s.max_inbox_depth);
    println!();
    println!("stability:");
    println!("  drops_per_tick: {:.4}", m.drops_per_tick);
    println!("  resource_drops_per_tick: {:.4}", m.resource_drops_per_tick);
    println!("  air_tx_success_ratio: {:.4}", m.air_tx_success_ratio);
    println!("  avg_route_table_utilization: {:.4}", m.avg_route_table_utilization);
    let recv_ratio = s.announces_received as f64 / s.announces_sent.max(1) as f64;
    println!("  announces recv/sent ratio: {:.4}", recv_ratio);
}
