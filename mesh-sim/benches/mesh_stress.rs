use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use reticulum_mesh_sim::{
    run_line_announce_benchmark, BenchmarkParams, MeshBandwidthBudget, MeshMemoryBudget,
};

fn bench_line_announce_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("line_announce_scaling");
    for nodes in [8_usize, 16, 32, 64] {
        group.bench_with_input(BenchmarkId::from_parameter(nodes), &nodes, |b, &n| {
            let params = BenchmarkParams {
                nodes: n,
                ticks: 32,
                radio_range: 1_000.0,
                spacing: 1.0,
                memory: MeshMemoryBudget {
                    inbox_limit: 16,
                    route_table_limit: n.max(1),
                    air_queue_limit: 256,
                },
                bandwidth: MeshBandwidthBudget {
                    packets_per_tick: 4,
                    latency_ticks: 1,
                    announce_interval: 1,
                },
            };
            b.iter(|| run_line_announce_benchmark(black_box(&params)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_line_announce_scaling);
criterion_main!(benches);
