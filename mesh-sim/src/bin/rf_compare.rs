//! Compare Wi-Fi HaLow vs LoRa-style gross bitrates on the same topology and load.
//!
//! Run: `cargo run -p reticulum-mesh-sim --release --bin rf_compare`
//!
//! LoRa uses [`SimConfig::medium_bit_bucket_max`] so bits accrue across ticks (real airtime does not
//! “reset” every simulated step). Without that, any frame larger than one tick’s bit grant could never
//! transmit—even on a 2-node link—which is a simulator artifact, not LoRa physics.
//!
//! **Calibration:** LoRa additionally uses [`SimConfig::stagger_announces`], a longer
//! [`MeshBandwidthBudget::announce_interval`] (seconds-scale wall time), and
//! [`SimConfig::medium_on_air_bytes_override`] so PHY budgeting matches short over-the-air frames
//! instead of the full logical `Packet` estimate. Without that, “every node floods every neighbor
//! every 50 ms with huge frames” is unrealistically harsh vs real ~10 kb/s mesh UX.

use reticulum_mesh_sim::{
    medium_bits_per_tick, run_line_announce_benchmark, BenchmarkParams, MeshBandwidthBudget,
    MeshMemoryBudget,
};

/// One simulation tick = 10 ms of wall time (chosen so ~10 Mb/s can carry many short
/// parallel copies per tick, while ~10 kb/s cannot).
const TICK_US: u64 = 10_000;
const HALOW_BPS: u64 = 10_000_000;
const LORA_BPS: u64 = 10_000;

/// Wall-time announce cadence: 3 s per node at `TICK_US` (orders of magnitude slower than 50 ms).
const ANNOUNCE_TICKS: u64 = 300;

/// Short LoRa / mesh MAC airtime for throughput debit only (~96 bits ≤ one 10 ms tick @ 10 kb/s).
const LORA_ON_AIR_BYTES: usize = 12;

fn main() {
    let nodes = 96usize;
    let ticks = 500u64;
    let spacing = 45.0f32;
    let range = 130.0f32;

    let memory = MeshMemoryBudget {
        inbox_limit: 512,
        route_table_limit: nodes.max(1),
        air_queue_limit: 250_000,
    };
    let bandwidth = MeshBandwidthBudget {
        packets_per_tick: 64,
        latency_ticks: 1,
        announce_interval: ANNOUNCE_TICKS,
    };

    let halow = run_line_announce_benchmark(&BenchmarkParams {
        nodes,
        ticks,
        radio_range: range,
        spacing,
        memory: memory.clone(),
        bandwidth: bandwidth.clone(),
        medium_throughput_bps: Some(HALOW_BPS),
        tick_duration_us: TICK_US,
        medium_bit_bucket_max: None,
        stagger_announces: true,
        medium_on_air_bytes_override: None,
    });

    let lora = run_line_announce_benchmark(&BenchmarkParams {
        nodes,
        ticks,
        radio_range: range,
        spacing,
        memory,
        bandwidth: bandwidth.clone(),
        medium_throughput_bps: Some(LORA_BPS),
        tick_duration_us: TICK_US,
        medium_bit_bucket_max: Some(200_000),
        stagger_announces: true,
        medium_on_air_bytes_override: Some(LORA_ON_AIR_BYTES),
    });

    let hb = medium_bits_per_tick(HALOW_BPS, TICK_US);
    let lb = medium_bits_per_tick(LORA_BPS, TICK_US);

    println!("RF comparison (same topology; LoRa profile calibrated for short MAC + stagger + slow announces)");
    println!(
        "  topology: {nodes} nodes, line spacing {spacing} m, range {range} m, {ticks} ticks × {TICK_US} µs/tick",
    );
    println!(
        "  offered load: announce every {} ticks (~{:.1} s wall), {} packets/tick, staggered phase; LoRa PHY debit ≈ {LORA_ON_AIR_BYTES} B/frame",
        bandwidth.announce_interval,
        (bandwidth.announce_interval as f64) * (TICK_US as f64) / 1_000_000.0,
        bandwidth.packets_per_tick
    );
    println!();
    println!(
        "Wi-Fi HaLow gross ~{HALOW_BPS} bit/s → ~{hb} bits (~{:.2} bytes) transferable on the medium per tick",
        hb as f64 / 8.0
    );
    print_report("HaLow", &halow.stats, &halow.stability);
    println!();
    println!(
        "LoRa gross ~{LORA_BPS} bit/s → ~{lb} bits (~{:.2} bytes) per tick",
        lb as f64 / 8.0
    );
    print_report("LoRa", &lora.stats, &lora.stability);
    println!();
    println!("Why LoRa can still show stress in this model:");
    println!(
        "  • dropped_throughput_limited = {} (PHY cannot carry all parallel copies of each broadcast)",
        lora.stats.dropped_throughput_limited
    );
    println!(
        "  • announces_received / announces_sent = {:.2} (broadcast: one send, many recv — ratio may exceed 1)",
        lora.stats.announces_received as f64 / lora.stats.announces_sent.max(1) as f64
    );
    println!(
        "  • avg route table fill = {:.3} vs HaLow {:.3}",
        lora.stability.avg_route_table_utilization,
        halow.stability.avg_route_table_utilization
    );
    println!(
        "  • air_tx_success_ratio: HaLow {:.3}, LoRa {:.3}",
        halow.stability.air_tx_success_ratio, lora.stability.air_tx_success_ratio
    );
}

fn print_report(
    name: &str,
    s: &reticulum_mesh_sim::SimStats,
    m: &reticulum_mesh_sim::StabilityMetrics,
) {
    println!("  [{name}] announces sent={} recv={}", s.announces_sent, s.announces_received);
    println!(
        "  [{name}] air: attempts={} ok={} | dropped throughput={} air_queue={} inbox={}",
        s.air_tx_attempts,
        s.air_tx_ok,
        s.dropped_throughput_limited,
        s.dropped_air_queue_full,
        s.dropped_inbox_full
    );
    println!(
        "  [{name}] stability: throughput_drops/tick={:.1}, resource_drops/tick={:.1}, max_air_q={}",
        m.throughput_drops_per_tick, m.resource_drops_per_tick, s.max_air_queue_depth
    );
}
