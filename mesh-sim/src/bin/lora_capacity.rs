//! Sweep node count for the same **calibrated** LoRa-class profile as `rf_compare` and report where the
//! medium stops keeping up (“flooding” in the throughput-limited sense).
//!
//! `cargo run -p reticulum-mesh-sim --release --bin lora_capacity`

use reticulum_mesh_sim::{
    medium_bits_per_tick, run_line_announce_benchmark, BenchmarkParams, MeshBandwidthBudget,
    MeshMemoryBudget,
};

const TICK_US: u64 = 10_000;
const LORA_BPS: u64 = 10_000;
const ANNOUNCE_TICKS: u64 = 300;
const LORA_ON_AIR_BYTES: usize = 12;

fn run(nodes: usize, ticks: u64) -> reticulum_mesh_sim::BenchmarkReport {
    let spacing = 45.0f32;
    let range = 130.0f32;
    run_line_announce_benchmark(&BenchmarkParams {
        nodes,
        ticks,
        radio_range: range,
        spacing,
        memory: MeshMemoryBudget {
            inbox_limit: 512,
            route_table_limit: nodes.max(1),
            air_queue_limit: 250_000,
        },
        bandwidth: MeshBandwidthBudget {
            packets_per_tick: 64,
            latency_ticks: 1,
            announce_interval: ANNOUNCE_TICKS,
        },
        medium_throughput_bps: Some(LORA_BPS),
        tick_duration_us: TICK_US,
        medium_bit_bucket_max: Some(200_000),
        stagger_announces: true,
        medium_on_air_bytes_override: Some(LORA_ON_AIR_BYTES),
    })
}

fn main() {
    let ticks = 500u64;
    println!(
        "LoRa profile (calibrated): {} bit/s, tick {} µs → {} bits/tick; bucket cap 200k bits;",
        LORA_BPS,
        TICK_US,
        medium_bits_per_tick(LORA_BPS, TICK_US)
    );
    println!(
        "  announce every {} ticks (~{:.1} s wall), staggered phases, PHY debit ≈ {} B/frame\n",
        ANNOUNCE_TICKS,
        (ANNOUNCE_TICKS as f64) * (TICK_US as f64) / 1_000_000.0,
        LORA_ON_AIR_BYTES
    );
    println!("Topology: line spacing 45 m, range 130 m; {ticks} sim ticks\n");

    println!(
        "{:>5} {:>7} {:>6} {:>8} {:>8} {:>8} {:>8} {:>6}",
        "nodes", "air_ok%", "recv/s", "thr_drop", "air_q", "inbox", "route%", "clog?"
    );

    let mut max_strict = 0usize;
    let mut max_air90 = 0usize;
    let mut max_air50 = 0usize;
    let mut max_recv_half = 0usize;

    for nodes in (2usize..=128).step_by(2) {
        let r = run(nodes, ticks);
        let s = &r.stats;
        let air_pct = 100.0 * s.air_tx_success_ratio();
        let recv_s = s.announces_received as f64 / s.announces_sent.max(1) as f64;
        let route_pct = 100.0 * r.stability.avg_route_table_utilization;
        let clog = s.is_clogged();

        println!(
            "{nodes:>5} {:>7.1} {:>6.3} {:>8} {:>8} {:>8} {:>7.1}% {:>6}",
            air_pct,
            recv_s,
            s.dropped_throughput_limited,
            s.dropped_air_queue_full,
            s.dropped_inbox_full,
            route_pct,
            if clog { "yes" } else { "no" }
        );

        if s.dropped_throughput_limited == 0 {
            max_strict = nodes;
        }
        if s.air_tx_success_ratio() >= 0.9 {
            max_air90 = nodes;
        }
        if s.air_tx_success_ratio() >= 0.5 {
            max_air50 = nodes;
        }
        if recv_s >= 0.5 {
            max_recv_half = nodes;
        }
    }

    println!("\nLargest node count observed in this sweep where:");
    println!(
        "  • Zero throughput drops (PHY kept up with every offered air copy): **≤ {max_strict}** nodes"
    );
    println!("  • Air success ≥ 90%: **≤ {max_air90}** nodes");
    println!("  • Air success ≥ 50%: **≤ {max_air50}** nodes");
    println!(
        "  • Announces recv/sent ≥ 0.5: **≤ {max_recv_half}** nodes (recv counts all listeners; can exceed sent)"
    );
    println!(
        "\nAggressive control traffic (short interval, no stagger, full logical packet airtime) shrinks these limits a lot—see README and `lora_sweep` for the harsher scenario."
    );
}
