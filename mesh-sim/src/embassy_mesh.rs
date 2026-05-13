//! Real [`reticulum::transport_embedded::EmbeddedTransport`] on [`embassy_executor::Executor`], with a shared greedy RF model (in-range delivery).
//!
//! - **Small integration harness** ([`run_three_node_line_relay_harness`]): one OS thread per node (easiest to reason about).
//! - **Large line stress** ([`run_line_scale_harness`]): **many nodes per worker thread** (sharded executors). Each worker runs one
//!   `Executor::run`; all [`EmbeddedTransport`] instances on that thread share the thread-local spawner ([`reticulum::async_backend::embassy::set_spawner`]).
//!   This is how you reach **hundreds to a few thousand** virtual nodes without thousands of pthread stacks.
//! - For **10k+** nodes at tick granularity without full `EmbeddedTransport`, use [`crate::MeshSim`] / [`crate::run_line_announce_benchmark`].
//!
//! Task pools are sized for up to [`MAX_NODES_PER_EMBASSY_SHARD`] concurrent instances **per worker** (`pool_size` is static in Embassy).

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::Duration as StdDuration;

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use reticulum::hash::AddressHash;
use reticulum::iface_messages::{RxMessage, TxMessage, TxMessageType};
use reticulum::packet::PacketType;
use reticulum::transport_embedded::{
    EmbeddedTransport, EmbeddedTransportConfig, EmbeddedTransportStats,
};

use crate::Position;

/// Maximum nodes scheduled on a **single** worker `Executor` in [`run_line_scale_harness`].
///
/// Must stay in sync with `pool_size` on the Embassy tasks used in that path (each logical node
/// spawns one instance per task type).
pub const MAX_NODES_PER_EMBASSY_SHARD: usize = 512;

fn div_ceil_uz(a: usize, b: usize) -> usize {
    debug_assert!(b > 0);
    a.div_ceil(b)
}

/// Parameters for [`run_line_scale_harness`]: announce-only traffic on a line, many real transports.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbassyLineScaleParams {
    pub nodes: usize,
    /// How many OS threads run `Executor::run`. Each thread hosts up to [`MAX_NODES_PER_EMBASSY_SHARD`] nodes.
    pub worker_threads: usize,
    pub spacing: f32,
    pub range: f32,
    pub announce_period_ms: u64,
    pub run_for: StdDuration,
    pub channel_capacity: usize,
    /// Wall-clock time to wait for all node reports after workers have started.
    pub collect_timeout: StdDuration,
}

impl Default for EmbassyLineScaleParams {
    fn default() -> Self {
        let worker_threads = std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 32))
            .unwrap_or(4);
        Self {
            nodes: 64,
            worker_threads,
            spacing: 50.0,
            range: 60.0,
            announce_period_ms: 120,
            run_for: StdDuration::from_secs(4),
            channel_capacity: 64,
            collect_timeout: StdDuration::from_secs(120),
        }
    }
}

/// Per-node counter snapshots after a scale run (index matches line topology order).
#[derive(Debug, Clone, PartialEq)]
pub struct EmbassyLineScaleReport {
    pub params: EmbassyLineScaleParams,
    pub node_stats: Vec<EmbeddedTransportStats>,
}

/// Run `params.nodes` [`EmbeddedTransport`] stacks on a line, with RF forwarding like [`medium_loop`].
///
/// Workers are pinned to contiguous index ranges; each worker runs one Embassy executor and one spawner.
/// Fails if `ceil(nodes / worker_threads) > `[`MAX_NODES_PER_EMBASSY_SHARD`].
pub fn run_line_scale_harness(
    params: &EmbassyLineScaleParams,
) -> Result<EmbassyLineScaleReport, &'static str> {
    if params.nodes == 0 {
        return Err("nodes must be > 0");
    }
    let workers = params.worker_threads.max(1);
    let per_shard = div_ceil_uz(params.nodes, workers);
    if per_shard > MAX_NODES_PER_EMBASSY_SHARD {
        return Err(
            "too many nodes per worker for Embassy static task pools; raise worker_threads or MAX_NODES_PER_EMBASSY_SHARD",
        );
    }

    let topo = RfTopology::line(params.nodes, params.spacing, params.range);

    let (medium_tx, medium_rx) = mpsc::channel::<(usize, TxMessage)>();
    let air: Vec<(mpsc::Sender<RxMessage>, mpsc::Receiver<RxMessage>)> =
        (0..params.nodes).map(|_| mpsc::channel()).collect();
    let to_air: Vec<mpsc::Sender<RxMessage>> = air.iter().map(|(tx, _)| tx.clone()).collect();
    let mut remaining_rx: std::collections::VecDeque<mpsc::Receiver<RxMessage>> =
        air.into_iter().map(|(_, rx)| rx).collect();

    let topo_med = topo.clone();
    let to_air_med = to_air.clone();
    thread::spawn(move || medium_loop(topo_med, to_air_med, medium_rx));

    let (report_tx, report_rx) = mpsc::channel::<NodeReport>();
    let announce = Duration::from_millis(params.announce_period_ms);
    let run_ms_u128 = params.run_for.as_millis().min(u128::from(u64::MAX));
    let run_for_embassy = Duration::from_millis(run_ms_u128 as u64);

    for w in 0..workers {
        let start = w * per_shard;
        if start >= params.nodes {
            break;
        }
        let end = (start + per_shard).min(params.nodes);
        let mut chunk_rx = Vec::with_capacity(end - start);
        for _ in start..end {
            chunk_rx.push(
                remaining_rx
                    .pop_front()
                    .expect("receiver count matches topology"),
            );
        }

        let medium_tx = medium_tx.clone();
        let topo_t = topo.clone();
        let rpt = report_tx.clone();
        let cap = params.channel_capacity;
        thread::spawn(move || {
            run_executor_shard(start..end, chunk_rx, topo_t, cap, medium_tx, announce, run_for_embassy, rpt);
        });
    }
    drop(medium_tx);
    drop(report_tx);

    let mut by_idx: HashMap<usize, EmbeddedTransportStats> = HashMap::new();
    let deadline = params.collect_timeout;
    let start = std::time::Instant::now();
    while by_idx.len() < params.nodes {
        if start.elapsed() > deadline {
            return Err("timeout waiting for scale node reports");
        }
        match report_rx.recv_timeout(StdDuration::from_millis(200)) {
            Ok(NodeReport::End { idx, stats }) => {
                by_idx.insert(idx, stats);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if by_idx.len() < params.nodes {
                    return Err("report channel disconnected early");
                }
                break;
            }
        }
    }

    let mut node_stats = Vec::with_capacity(params.nodes);
    for i in 0..params.nodes {
        let stats = by_idx.remove(&i).ok_or("missing stats for node index")?;
        node_stats.push(stats);
    }

    Ok(EmbassyLineScaleReport {
        params: params.clone(),
        node_stats,
    })
}

/// Static node layout and link budget for the virtual medium.
#[derive(Debug, Clone)]
pub struct RfTopology {
    pub positions: Vec<Position>,
    pub range: f32,
    pub addresses: Vec<AddressHash>,
}

impl RfTopology {
    /// Chain nodes on the X axis; addresses are deterministic hashes of node index.
    pub fn line(node_count: usize, spacing: f32, range: f32) -> Self {
        let mut positions = Vec::with_capacity(node_count);
        let mut addresses = Vec::with_capacity(node_count);
        for i in 0..node_count {
            positions.push(Position {
                x: i as f32 * spacing,
                y: 0.0,
            });
            let ib = (i as u64).to_le_bytes();
            addresses.push(AddressHash::new_from_slice(&ib));
        }
        Self {
            positions,
            range,
            addresses,
        }
    }

    fn in_range(&self, i: usize, j: usize) -> bool {
        if i == j {
            return false;
        }
        self.positions[i].distance_to(self.positions[j]) <= self.range
    }
}

#[derive(Debug)]
enum NodeReport {
    End {
        idx: usize,
        stats: EmbeddedTransportStats,
    },
}

/// Collected stats after [`run_three_node_line_relay_harness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbassyRelayReport {
    pub node_a_stats: EmbeddedTransportStats,
    pub node_b_stats: EmbeddedTransportStats,
    pub node_c_stats: EmbeddedTransportStats,
}

/// Three-hop chain A—B—C over real embedded transport (B relays). One Embassy executor + OS thread per **logical** node.
///
/// Node C echoes one data packet back to A; A must receive the ack through B.
pub fn run_three_node_line_relay_harness() -> Result<EmbassyRelayReport, &'static str> {
    const SPACING: f32 = 50.0;
    const RANGE: f32 = 60.0;
    let topo = RfTopology::line(3, SPACING, RANGE);

    let (medium_tx, medium_rx) = mpsc::channel::<(usize, TxMessage)>();
    let air: Vec<(mpsc::Sender<RxMessage>, mpsc::Receiver<RxMessage>)> =
        (0..3).map(|_| mpsc::channel()).collect();
    let to_air: Vec<mpsc::Sender<RxMessage>> = air.iter().map(|(tx, _)| tx.clone()).collect();
    let mut from_air: Vec<mpsc::Receiver<RxMessage>> = air.into_iter().map(|(_, rx)| rx).collect();

    let topo_med = topo.clone();
    let to_air_med = to_air.clone();
    thread::spawn(move || medium_loop(topo_med, to_air_med, medium_rx));

    let (report_tx, report_rx) = mpsc::channel::<NodeReport>();

    for idx in 0usize..3 {
        let medium_tx = medium_tx.clone();
        let rx = from_air.remove(0);
        let topo_t = topo.clone();
        let rpt = report_tx.clone();
        thread::spawn(move || run_executor_for_node(idx, topo_t, medium_tx, rx, rpt));
    }
    drop(report_tx);

    let mut by_idx: HashMap<usize, NodeReport> = HashMap::new();
    let deadline = StdDuration::from_secs(12);
    let start = std::time::Instant::now();
    while by_idx.len() < 3 {
        if start.elapsed() > deadline {
            return Err("timeout waiting for node reports");
        }
        match report_rx.recv_timeout(StdDuration::from_millis(150)) {
            Ok(r) => {
                let k = match &r {
                    NodeReport::End { idx, .. } => *idx,
                };
                by_idx.insert(k, r);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if by_idx.len() < 3 {
                    return Err("report channel disconnected early");
                }
                break;
            }
        }
    }

    let node_a_stats = match by_idx.remove(&0) {
        Some(NodeReport::End { idx: 0, stats }) => stats,
        _ => return Err("missing node A report"),
    };

    let node_b_stats = match by_idx.remove(&1) {
        Some(NodeReport::End { idx: 1, stats }) => stats,
        _ => return Err("missing node B report"),
    };

    let node_c_stats = match by_idx.remove(&2) {
        Some(NodeReport::End { idx: 2, stats }) => stats,
        _ => return Err("missing node C report"),
    };

    Ok(EmbassyRelayReport {
        node_a_stats,
        node_b_stats,
        node_c_stats,
    })
}

fn medium_loop(
    topo: RfTopology,
    to_node: Vec<mpsc::Sender<RxMessage>>,
    medium_rx: mpsc::Receiver<(usize, TxMessage)>,
) {
    let n = topo.addresses.len();
    while let Ok((from_i, msg)) = medium_rx.recv() {
        if from_i >= n {
            continue;
        }
        let from_addr = topo.addresses[from_i];
        let packet = msg.packet;
        match msg.tx_type {
            TxMessageType::Broadcast(exclude) => {
                for (j, tx) in to_node.iter().enumerate() {
                    if j == from_i || !topo.in_range(from_i, j) {
                        continue;
                    }
                    let addr_j = topo.addresses[j];
                    if exclude == Some(addr_j) {
                        continue;
                    }
                    let _ = tx.send(RxMessage {
                        address: from_addr,
                        packet,
                    });
                }
            }
            TxMessageType::Direct(dest) => {
                if let Some(j) = topo.addresses.iter().position(|a| *a == dest) {
                    if j != from_i && topo.in_range(from_i, j) {
                        let _ = to_node[j].send(RxMessage {
                            address: from_addr,
                            packet,
                        });
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_executor_shard(
    global_range: std::ops::Range<usize>,
    chunk_rx: Vec<mpsc::Receiver<RxMessage>>,
    topo: RfTopology,
    channel_capacity: usize,
    medium_tx: mpsc::Sender<(usize, TxMessage)>,
    announce_period: Duration,
    run_for: Duration,
    report: mpsc::Sender<NodeReport>,
) {
    debug_assert_eq!(global_range.end - global_range.start, chunk_rx.len());
    let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
    executor.run(|spawner| {
        reticulum::async_backend::embassy::set_spawner(spawner);
        for (offset, air_rx) in chunk_rx.into_iter().enumerate() {
            let i = global_range.start + offset;
            let my_addr = topo.addresses[i];
            let node = make_node_with_capacity(my_addr, channel_capacity);
            spawner
                .spawn(scale_node_entry(
                    i,
                    my_addr,
                    node,
                    medium_tx.clone(),
                    air_rx,
                    announce_period,
                    run_for,
                    report.clone(),
                ))
                .unwrap();
        }
    });
}

fn run_executor_for_node(
    idx: usize,
    topo: RfTopology,
    medium_tx: mpsc::Sender<(usize, TxMessage)>,
    air_rx: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<NodeReport>,
) {
    let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
    let i = idx;
    let my_addr = topo.addresses[i];

    executor.run(|spawner| {
        reticulum::async_backend::embassy::set_spawner(spawner);
        // `EmbeddedTransport::new` spawns runner tasks — spawner must already be set (this thread).
        let node = make_node(my_addr);
        spawner
            .spawn(node_entry(
                idx, i, topo, my_addr, node, medium_tx, air_rx, report,
            ))
            .unwrap();
    });
}

fn make_node_with_capacity(
    local_address: AddressHash,
    channel_capacity: usize,
) -> &'static EmbeddedTransport {
    Box::leak(Box::new(EmbeddedTransport::new(EmbeddedTransportConfig {
        channel_capacity,
        broadcast_enabled: true,
        local_address: Some(local_address),
        ..EmbeddedTransportConfig::default()
    })))
}

fn make_node(local_address: AddressHash) -> &'static EmbeddedTransport {
    make_node_with_capacity(local_address, 64)
}

#[embassy_executor::task(pool_size = 512)]
#[allow(clippy::too_many_arguments)]
async fn scale_node_entry(
    idx: usize,
    my_addr: AddressHash,
    node: &'static EmbeddedTransport,
    medium_tx: mpsc::Sender<(usize, TxMessage)>,
    air_rx: mpsc::Receiver<RxMessage>,
    announce_period: Duration,
    run_for: Duration,
    report: mpsc::Sender<NodeReport>,
) {
    let sp = Spawner::for_current_executor().await;
    sp.spawn(virtual_air_to_medium(idx, node, medium_tx.clone()))
        .unwrap();
    sp.spawn(virtual_air_in(node, air_rx)).unwrap();
    sp.spawn(periodic_announce_period(node, my_addr, announce_period))
        .unwrap();
    sp.spawn(scale_report_after(idx, node, run_for, report)).unwrap();
}

#[embassy_executor::task(pool_size = 512)]
async fn scale_report_after(
    idx: usize,
    node: &'static EmbeddedTransport,
    run_for: Duration,
    report: mpsc::Sender<NodeReport>,
) {
    Timer::after(run_for).await;
    let _ = report.send(NodeReport::End {
        idx,
        stats: node.stats(),
    });
}

#[embassy_executor::task(pool_size = 512)]
#[allow(clippy::too_many_arguments)]
async fn node_entry(
    idx: usize,
    i: usize,
    topo: RfTopology,
    my_addr: AddressHash,
    node: &'static EmbeddedTransport,
    medium_tx: mpsc::Sender<(usize, TxMessage)>,
    air_rx: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<NodeReport>,
) {
    let addr_a = topo.addresses[0];
    let addr_c = topo.addresses[2];
    let sp = Spawner::for_current_executor().await;
    sp.spawn(virtual_air_to_medium(i, node, medium_tx)).unwrap();
    sp.spawn(virtual_air_in(node, air_rx)).unwrap();
    sp.spawn(periodic_announce(node, my_addr)).unwrap();

    match idx {
        0 => {
            sp.spawn(node_a_client(node, addr_c, report)).unwrap();
        }
        2 => {
            sp.spawn(node_c_echo(addr_a, addr_c, node)).unwrap();
            sp.spawn(node_stats_after_delay(idx, node, report)).unwrap();
        }
        _ => {
            sp.spawn(node_stats_after_delay(idx, node, report)).unwrap();
        }
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn periodic_announce(node: &'static EmbeddedTransport, addr: AddressHash) {
    loop {
        node.request_synthetic_bytes(PacketType::Announce, addr, &[]);
        Timer::after(Duration::from_millis(120)).await;
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn periodic_announce_period(
    node: &'static EmbeddedTransport,
    addr: AddressHash,
    every: Duration,
) {
    loop {
        node.request_synthetic_bytes(PacketType::Announce, addr, &[]);
        Timer::after(every).await;
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn virtual_air_to_medium(
    node_idx: usize,
    transport: &'static EmbeddedTransport,
    medium: mpsc::Sender<(usize, TxMessage)>,
) {
    let mut egress = transport.egress_receiver();
    loop {
        if let Ok(message) = egress.recv().await {
            let _ = medium.send((node_idx, message));
        }
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn virtual_air_in(node: &'static EmbeddedTransport, rx: mpsc::Receiver<RxMessage>) {
    loop {
        match rx.try_recv() {
            Ok(msg) => node.inject_from_interface(msg),
            Err(mpsc::TryRecvError::Empty) => Timer::after(Duration::from_millis(1)).await,
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn node_a_client(
    node_a: &'static EmbeddedTransport,
    node_c_addr: AddressHash,
    report: mpsc::Sender<NodeReport>,
) {
    Timer::after(Duration::from_millis(900)).await;

    let baseline = node_a.stats().data_deliver_local_count;
    node_a.request_synthetic_bytes(PacketType::Data, node_c_addr, b"embassy-mesh-relay");

    let wait = Duration::from_secs(10);
    let start = embassy_time::Instant::now();
    while node_a.stats().data_deliver_local_count <= baseline {
        if start.elapsed() >= wait {
            break;
        }
        Timer::after(Duration::from_millis(15)).await;
    }

    Timer::after(Duration::from_millis(80)).await;
    let _ = report.send(NodeReport::End {
        idx: 0usize,
        stats: node_a.stats(),
    });
}

#[embassy_executor::task(pool_size = 512)]
async fn node_c_echo(
    node_a_addr: AddressHash,
    _node_c_addr: AddressHash,
    node_c: &'static EmbeddedTransport,
) {
    let mut baseline = node_c.stats().data_deliver_local_count;
    loop {
        if node_c.stats().data_deliver_local_count > baseline {
            node_c.request_synthetic_bytes(PacketType::Data, node_a_addr, b"ack-relay-via-b");
            baseline = node_c.stats().data_deliver_local_count;
        }
        Timer::after(Duration::from_millis(10)).await;
    }
}

#[embassy_executor::task(pool_size = 512)]
async fn node_stats_after_delay(
    idx: usize,
    node: &'static EmbeddedTransport,
    report: mpsc::Sender<NodeReport>,
) {
    Timer::after(Duration::from_secs(3)).await;
    let _ = report.send(NodeReport::End {
        idx,
        stats: node.stats(),
    });
}
