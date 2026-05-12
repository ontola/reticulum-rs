//! LoRa-class bitrate sweeps: **harsh** (unrealistic control-plane load) vs **calibrated** (short MAC
//! airtime, staggered announces, slow Meshtastic-scale cadence)—same knobs as `rf_compare`.
//!
//! Run: `cargo run -p reticulum-mesh-sim --release --bin lora_sweep`

use reticulum::packet::Packet;
use reticulum_mesh_sim::{
    medium_bits_per_tick, run_line_announce_benchmark, BenchmarkParams, MeshBandwidthBudget,
    MeshMemoryBudget,
};

const LORA_BPS: u64 = 10_000;
const TICK_10MS: u64 = 10_000;
const TICK_50MS: u64 = 50_000;
const ANNOUNCE_CAL: u64 = 300;
const LORA_ON_AIR_BYTES: usize = 12;

fn lora_run_harsh(nodes: usize, ticks: u64, tick_us: u64) -> reticulum_mesh_sim::BenchmarkReport {
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
            announce_interval: 5,
        },
        medium_throughput_bps: Some(LORA_BPS),
        tick_duration_us: tick_us,
        medium_bit_bucket_max: Some(200_000),
        stagger_announces: false,
        medium_on_air_bytes_override: None,
    })
}

fn lora_run_calibrated(
    nodes: usize,
    ticks: u64,
    tick_us: u64,
) -> reticulum_mesh_sim::BenchmarkReport {
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
            announce_interval: ANNOUNCE_CAL,
        },
        medium_throughput_bps: Some(LORA_BPS),
        tick_duration_us: tick_us,
        medium_bit_bucket_max: Some(200_000),
        stagger_announces: true,
        medium_on_air_bytes_override: Some(LORA_ON_AIR_BYTES),
    })
}

fn main() {
    let b10 = medium_bits_per_tick(LORA_BPS, TICK_10MS);
    let b50 = medium_bits_per_tick(LORA_BPS, TICK_50MS);
    println!("LoRa-class gross PHY: {LORA_BPS} bit/s");
    println!(
        "  bits/tick @ 10ms tick = {b10} (~{:.1} B), @ 50ms tick = {b50} (~{:.1} B)",
        b10 as f64 / 8.0,
        b50 as f64 / 8.0
    );
    println!(
        "  full logical announce ≈ {} B ({} bits) — see `approx_packet_on_air_bytes`\n",
        reticulum_mesh_sim::approx_packet_on_air_bytes(&Packet::default()),
        reticulum_mesh_sim::approx_packet_on_air_bytes(&Packet::default()) * 8
    );

    println!("A) Harsh control plane: announce every 5 ticks, no stagger, full logical airtime — starves at ~10 kb/s.");
    for &n in &[2usize, 4, 8] {
        let r = lora_run_harsh(n, 300, TICK_10MS);
        let s = &r.stats;
        println!(
            "   nodes={n} announces recv={} sent={} air_ok={} throughput_drops={}",
            s.announces_received,
            s.announces_sent,
            s.air_tx_ok,
            s.dropped_throughput_limited
        );
    }

    println!("\nB) Calibrated (short MAC debit, stagger, ~3 s announces): 50 ms tick sweep.");
    println!("   {:>5} {:>14} {:>8} {:>8} {:>14} {:>10}", "nodes", "ann recv", "sent", "air_ok", "thr_drop", "recv/sent");
    for &n in &[
        2usize, 4, 6, 8, 10, 12, 14, 16, 20, 24, 32, 40, 48, 56, 64,
    ] {
        let r = lora_run_calibrated(n, 800, TICK_50MS);
        let s = &r.stats;
        let ratio = s.announces_received as f64 / s.announces_sent.max(1) as f64;
        println!(
            "   {:>5} {:>14} {:>8} {:>8} {:>14} {:>10.3}",
            n, s.announces_received, s.announces_sent, s.air_tx_ok, s.dropped_throughput_limited, ratio
        );
    }

    println!("\nSee `rf_compare` / `lora_capacity` for the 10 ms tick + 3 s announce calibration used for HaLow vs LoRa tables.");
}
