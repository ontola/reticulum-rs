//! Minimal CLI for quick mesh-sim runs and parameter smoke tests.

use std::process;

use reticulum_mesh_sim::{run_line_announce_benchmark, BenchmarkParams};

fn print_usage() {
    eprintln!(
        "\
Usage: reticulum-mesh-sim [options]

Run a line-topology announce stress scenario and print stability metrics.
For 1k+ nodes, build with `cargo run --release` so the spatial index and air queue stay fast.

Options:
  --nodes <N>     Number of nodes (default: 32)
  --ticks <T>     Simulation ticks (default: 64)
  --spacing <M>   Meters between adjacent nodes on the line (default: 1.0)
  --range <M>     Radio range (default: 1000)
  --air-queue <N> Shared air queue capacity (default: from MeshMemoryBudget default)
  --inbox <N>     Per-node inbox limit (default: from MeshMemoryBudget default)
  --routes <N>    Per-node route table capacity (default: from MeshMemoryBudget default)
  --ppt <N>       Packets processed per node per tick (default: 8)
  --announce <T>  Ticks between announces (default: 10)
  --latency <T>   One-way air latency in ticks (default: 1)
  -h, --help      Show this help
"
    );
}

fn main() {
    let mut params = BenchmarkParams::default();

    let mut argv = std::env::args().skip(1).peekable();
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            "--nodes" => {
                params.nodes = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--nodes requires a positive integer"));
                if params.nodes == 0 {
                    usage_error("--nodes must be >= 1");
                }
            }
            "--ticks" => {
                params.ticks = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--ticks requires an integer"));
            }
            "--spacing" => {
                params.spacing = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--spacing requires a number"));
            }
            "--range" => {
                params.radio_range = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--range requires a number"));
            }
            "--air-queue" => {
                params.memory.air_queue_limit = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--air-queue requires an integer"));
            }
            "--inbox" => {
                params.memory.inbox_limit = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--inbox requires an integer"));
            }
            "--routes" => {
                params.memory.route_table_limit = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--routes requires an integer"));
            }
            "--ppt" => {
                params.bandwidth.packets_per_tick = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--ppt requires an integer"));
            }
            "--announce" => {
                params.bandwidth.announce_interval = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--announce requires an integer"));
            }
            "--latency" => {
                params.bandwidth.latency_ticks = argv
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage_error("--latency requires an integer"));
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                process::exit(2);
            }
        }
    }

    let report = run_line_announce_benchmark(&params);
    let s = &report.stats;
    let m = &report.stability;

    println!("mesh-sim line announce benchmark");
    println!("  nodes={} ticks={} spacing={} range={}", params.nodes, params.ticks, params.spacing, params.radio_range);
    println!("  memory: air_queue={} inbox={} routes={}", params.memory.air_queue_limit, params.memory.inbox_limit, params.memory.route_table_limit);
    println!("  bandwidth: ppt={} announce_interval={} latency_ticks={}", params.bandwidth.packets_per_tick, params.bandwidth.announce_interval, params.bandwidth.latency_ticks);
    println!();
    println!("traffic: announces_sent={} announces_recv={} air_tx_attempts={} air_tx_ok={}", s.announces_sent, s.announces_received, s.air_tx_attempts, s.air_tx_ok);
    println!("data: sent={} delivered={} forwarded={}", s.data_sent, s.data_delivered, s.data_forwarded);
    println!("drops: total={} resource_pressure={} (air_full={} inbox_full={} route_full={})", s.dropped_total(), s.dropped_resource_pressure(), s.dropped_air_queue_full, s.dropped_inbox_full, s.dropped_route_table_full);
    println!("queues: max_air={} max_inbox={}", s.max_air_queue_depth, s.max_inbox_depth);
    println!();
    println!("stability:");
    println!("  drops_per_tick: {:.4}", m.drops_per_tick);
    println!("  resource_drops_per_tick: {:.4}", m.resource_drops_per_tick);
    println!("  air_tx_success_ratio: {:.4}", m.air_tx_success_ratio);
    println!("  avg_route_table_utilization: {:.4}", m.avg_route_table_utilization);
    if let Some(r) = m.data_delivery_ratio {
        println!("  data_delivery_ratio: {:.4}", r);
    }
}

fn usage_error(msg: &str) -> ! {
    eprintln!("{msg}");
    print_usage();
    process::exit(2);
}
