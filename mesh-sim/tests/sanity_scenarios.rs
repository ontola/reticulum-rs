//! Behavioural sanity checks: zero memory, spatial congestion (“interference”), healthy spread,
//! and reachability vs hop-cap / distance.
//!
//! Note: routing tables only learn destinations from **directly heard** announces, so end-to-end
//! data in this simulator matches short relay chains (see unit `relay_forwards_data_across_three_node_line`).
//! “Larger area” is expressed as **partition** (out of range) and **hop limit** policy, not kilometre-wide multi-hop vectors.

use reticulum_mesh_sim::{
    medium_bits_per_tick, DropReason, MeshSim, NodeConfig, Position, RadioConfig, SimConfig,
};

fn lora_like_phy() -> SimConfig {
    let tick_us = 10_000u64;
    SimConfig {
        radio: RadioConfig {
            range: 200.0,
            latency_ticks: 1,
            air_queue_limit: 50_000,
        },
        medium_throughput_bps: Some(100_000),
        tick_duration_us: tick_us,
        medium_bit_bucket_max: Some(500_000),
        medium_on_air_bytes_override: Some(16),
        stagger_announces: false,
        ..Default::default()
    }
}

#[test]
fn zero_memory_capacity_records_failures() {
    // No air queue, no inbox, no route table: nothing can be stored or forwarded.
    let mut sim = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 100.0,
            latency_ticks: 1,
            air_queue_limit: 0,
        },
        ..Default::default()
    });
    let dead = NodeConfig {
        inbox_limit: 0,
        route_table_limit: 0,
        packets_per_tick: 8,
        announce_interval: 5,
    };
    sim.add_node(Position { x: 0.0, y: 0.0 }, dead.clone());
    sim.add_node(Position { x: 20.0, y: 0.0 }, dead);
    sim.run_ticks(30);

    let s = sim.stats();
    assert!(
        s.dropped_air_queue_full > 0
            || s.dropped_inbox_full > 0
            || s.dropped_route_table_full > 0,
        "expected at least one buffer/table drop with zero capacity, got stats={s:?}"
    );
    assert_eq!(s.data_delivered, 0);
}

#[test]
fn colocated_nodes_starve_air_more_than_spread_out() {
    let ticks = 250u64;
    let announce = 2u64;
    let nodes = 100usize;

    let mut crowded = MeshSim::new(lora_like_phy());
    let cfg = NodeConfig {
        inbox_limit: 2_048,
        route_table_limit: nodes,
        packets_per_tick: 64,
        announce_interval: announce,
    };
    for _ in 0..nodes {
        crowded.add_node(Position { x: 0.0, y: 0.0 }, cfg.clone());
    }
    crowded.run_ticks(ticks);
    let air_ok_crowd = crowded.stats().air_tx_success_ratio();

    let mut spread = MeshSim::new(lora_like_phy());
    for i in 0..nodes {
        spread.add_node(
            Position {
                x: i as f32 * 55.0,
                y: 0.0,
            },
            cfg.clone(),
        );
    }
    spread.run_ticks(ticks);
    let air_ok_spread = spread.stats().air_tx_success_ratio();

    assert!(
        air_ok_spread > air_ok_crowd,
        "expected a spread RF neighborhood to suffer fewer successful air enqueues than one pile-up cell \
         (crowded={air_ok_crowd:.4} vs spread={air_ok_spread:.4}); bits/tick={}",
        medium_bits_per_tick(100_000, 10_000)
    );
    assert!(
        crowded.stats().dropped_resource_pressure() > spread.stats().dropped_resource_pressure(),
        "expected more PHY/buffer pressure when all nodes share one collision domain"
    );
}

#[test]
fn spread_cluster_delivers_many_announces_under_unlimited_phy() {
    // Isolate “geometry helps” from gross bitrate: unlimited medium, same cadence as stress cases.
    let nodes = 100usize;
    let mut sim = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 200.0,
            latency_ticks: 1,
            air_queue_limit: 250_000,
        },
        medium_throughput_bps: None,
        ..Default::default()
    });
    let cfg = NodeConfig {
        inbox_limit: 2_048,
        route_table_limit: nodes,
        packets_per_tick: 64,
        announce_interval: 2,
    };
    for i in 0..nodes {
        sim.add_node(
            Position {
                x: i as f32 * 55.0,
                y: 0.0,
            },
            cfg.clone(),
        );
    }
    sim.run_ticks(300);

    let s = sim.stats();
    let recv_per_sent = s.announces_received as f64 / s.announces_sent.max(1) as f64;
    assert!(
        s.announces_received > 50_000,
        "expected most announce copies to land with unlimited PHY + spread geometry, got {}",
        s.announces_received
    );
    assert!(
        recv_per_sent > 4.0,
        "broadcast ⇒ recv/sent > 1 (several neighbors per sender); got {recv_per_sent:.2}"
    );
    assert_eq!(s.dropped_throughput_limited, 0);
}

#[test]
fn larger_distance_partitions_link() {
    let cfg = NodeConfig {
        inbox_limit: 256,
        route_table_limit: 8,
        packets_per_tick: 16,
        announce_interval: 5,
    };

    let mut close = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 80.0,
            latency_ticks: 1,
            air_queue_limit: 8_192,
        },
        ..Default::default()
    });
    close.add_node(Position { x: 0.0, y: 0.0 }, cfg.clone());
    close.add_node(Position { x: 25.0, y: 0.0 }, cfg.clone());
    close.run_ticks(25);
    close
        .send_data(0, close.node(1).address(), b"ping")
        .expect("in-range pair should accept data");
    close.run_ticks(15);
    assert!(
        close.stats().data_delivered >= 1,
        "close nodes should deliver: {:?}",
        close.stats()
    );

    let mut far = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 80.0,
            latency_ticks: 1,
            air_queue_limit: 8_192,
        },
        ..Default::default()
    });
    far.add_node(Position { x: 0.0, y: 0.0 }, cfg.clone());
    far.add_node(Position { x: 500.0, y: 0.0 }, cfg.clone());
    far.run_ticks(25);
    let send = far.send_data(0, far.node(1).address(), b"lost");
    assert!(
        send == Err(DropReason::OutOfRange),
        "expected immediate out-of-range for first hop, got {send:?}"
    );
}

#[test]
fn hop_cap_blocks_relay_that_would_otherwise_work() {
    // 3-node relay (matches core unit test topology); max_packet_hops = 0 drops at first forward.
    let pos = |i: f32| Position { x: i * 50.0, y: 0.0 };

    let mut blocked = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 60.0,
            latency_ticks: 1,
            air_queue_limit: 256,
        },
        max_packet_hops: 0,
        ..Default::default()
    });
    let cfg = NodeConfig {
        inbox_limit: 64,
        route_table_limit: 8,
        packets_per_tick: 8,
        announce_interval: 3,
    };
    blocked.add_node(pos(0.0), cfg.clone());
    blocked.add_node(pos(1.0), cfg.clone());
    blocked.add_node(pos(2.0), cfg.clone());
    blocked.run_ticks(20);
    let dest = blocked.node(2).address();
    blocked.send_data(0, dest, b"no").unwrap();
    blocked.run_ticks(15);
    assert_eq!(blocked.stats().data_delivered, 0);
    assert!(
        blocked.stats().dropped_hop_limit > 0,
        "expected HopLimit on relay; stats={:?}",
        blocked.stats()
    );

    let mut ok = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: 60.0,
            latency_ticks: 1,
            air_queue_limit: 256,
        },
        max_packet_hops: 8,
        ..Default::default()
    });
    ok.add_node(pos(0.0), cfg.clone());
    ok.add_node(pos(1.0), cfg.clone());
    ok.add_node(pos(2.0), cfg.clone());
    ok.run_ticks(20);
    let dest = ok.node(2).address();
    ok.send_data(0, dest, b"yes").unwrap();
    ok.run_ticks(15);
    assert!(
        ok.stats().data_delivered >= 1,
        "same topology with headroom should deliver: {:?}",
        ok.stats()
    );
    assert_eq!(ok.stats().dropped_hop_limit, 0);
}
