//! Large-scale host-side mesh simulator for reticulum-rs.
//!
//! This crate is intentionally separate from the core `reticulum` crate. The
//! simulator models virtual radio conditions around Reticulum packet boundaries
//! instead of reimplementing core protocol policy in the main crate.
//!
//! For experiments over node count, buffer sizes, and processing budget, see
//! [`BenchmarkParams`], [`run_line_announce_benchmark`], and [`StabilityMetrics`].
//! Run `cargo bench -p reticulum-mesh-sim --bench mesh_stress` for Criterion timing.
//!
//! **Many nodes + real `EmbeddedTransport`:** [`embassy_mesh::run_line_scale_harness`] shards nodes across workers (each worker = one `Executor`; see [`embassy_mesh::MAX_NODES_PER_EMBASSY_SHARD`]). **Very large (10k+)** tick-level studies: [`MeshSim`] / [`run_line_announce_benchmark`].
//!
//! **Large meshes (1k–10k+ nodes):** use a `--release` binary; broadcasts use a
//! per-tick spatial grid and `Arc` shared packets to avoid naive full-mesh cost and buffer clones per neighbor.

pub mod embassy_mesh;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use reticulum::hash::AddressHash;
use reticulum::packet::{Packet, PacketDataBuffer, PacketType};

pub type NodeId = usize;
pub type Tick = u64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    pub x: f32,
    pub y: f32,
}

impl Position {
    pub fn distance_to(self, other: Self) -> f32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt()
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub inbox_limit: usize,
    pub route_table_limit: usize,
    pub packets_per_tick: usize,
    pub announce_interval: Tick,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            inbox_limit: 64,
            route_table_limit: 256,
            packets_per_tick: 8,
            announce_interval: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RadioConfig {
    pub range: f32,
    pub latency_ticks: Tick,
    pub air_queue_limit: usize,
}

impl Default for RadioConfig {
    fn default() -> Self {
        Self {
            range: 100.0,
            latency_ticks: 1,
            air_queue_limit: 4096,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SimConfig {
    pub radio: RadioConfig,
    pub max_packet_hops: u8,
    /// Gross PHY bitrate of the shared wireless medium (bits per second).
    /// `None` means unlimited air capacity (legacy / stress without RF limits).
    pub medium_throughput_bps: Option<u64>,
    /// Wall-clock duration represented by one simulation tick, in **microseconds**.
    /// Used with [`SimConfig::medium_throughput_bps`] to compute per-tick air budget:
    /// `bits_per_tick = bps * tick_duration_us / 1_000_000`.
    pub tick_duration_us: u64,
    /// When set with [`SimConfig::medium_throughput_bps`], **unused** bits from prior ticks are
    /// carried forward up to this cap (`remaining = min(remaining + grant, cap)` each tick).
    /// When `None`, each tick **replaces** the budget with one grant only (stronger than physics:
    /// a frame longer than one tick’s bits can never be sent — often misleading for slow PHYs).
    pub medium_bit_bucket_max: Option<u64>,
    /// Spread nodes’ first announce across [`NodeConfig::announce_interval`] (reduces unrealistic
    /// “every node fires the same tick” load). Typical for real CSMA / scheduled UX.
    pub stagger_announces: bool,
    /// Fixed on-air size for throughput debit (bytes). When set, overrides [`approx_packet_on_air_bytes`]
    /// for budgeting only — useful for short LoRa/MAC frames while keeping logical `Packet`s.
    pub medium_on_air_bytes_override: Option<usize>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            radio: RadioConfig::default(),
            max_packet_hops: 8,
            medium_throughput_bps: None,
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        }
    }
}

/// Bits cleared on the medium each simulated tick from gross bitrate and tick duration.
#[must_use]
pub fn medium_bits_per_tick(throughput_bps: u64, tick_duration_us: u64) -> u64 {
    throughput_bps
        .saturating_mul(tick_duration_us)
        .saturating_div(1_000_000)
}

/// Very rough on-air size for throughput budgeting (single-destination Reticulum-like frame).
#[must_use]
pub fn approx_packet_on_air_bytes(packet: &Packet) -> usize {
    const FIXED: usize = 33 + 16 + 1;
    let transport = usize::from(packet.transport.is_some()) * 16;
    let ifac = packet
        .ifac
        .map(|i| 1usize.saturating_add(i.length))
        .unwrap_or(0);
    FIXED + transport + ifac + packet.data.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Offline,
    OutOfRange,
    AirQueueFull,
    /// Offered load exceeds the shared medium’s bitrate budget for this tick.
    ThroughputLimited,
    InboxFull,
    RouteTableFull,
    NoRoute,
    HopLimit,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimStats {
    pub ticks: Tick,
    pub announces_sent: u64,
    pub announces_received: u64,
    pub data_sent: u64,
    pub data_delivered: u64,
    pub data_forwarded: u64,
    /// Per-link attempts to enqueue onto the shared air queue (one per source/recipient pair).
    pub air_tx_attempts: u64,
    /// Subset of attempts that successfully entered the air queue.
    pub air_tx_ok: u64,
    pub dropped_offline: u64,
    pub dropped_out_of_range: u64,
    pub dropped_air_queue_full: u64,
    pub dropped_throughput_limited: u64,
    pub dropped_inbox_full: u64,
    pub dropped_route_table_full: u64,
    pub dropped_no_route: u64,
    pub dropped_hop_limit: u64,
    pub max_air_queue_depth: usize,
    pub max_inbox_depth: usize,
}

impl SimStats {
    pub fn dropped_total(&self) -> u64 {
        self.dropped_offline
            + self.dropped_out_of_range
            + self.dropped_air_queue_full
            + self.dropped_throughput_limited
            + self.dropped_inbox_full
            + self.dropped_route_table_full
            + self.dropped_no_route
            + self.dropped_hop_limit
    }

    /// Drops tied to finite buffers, routing tables, or **medium bitrate** (offered load vs capacity).
    pub fn dropped_resource_pressure(&self) -> u64 {
        self.dropped_air_queue_full
            + self.dropped_inbox_full
            + self.dropped_route_table_full
            + self.dropped_throughput_limited
    }

    pub fn is_clogged(&self) -> bool {
        self.dropped_air_queue_full > 0
            || self.dropped_inbox_full > 0
            || self.dropped_throughput_limited > 0
    }

    /// Successful air transmissions as a fraction of attempts (0..=1).
    pub fn air_tx_success_ratio(&self) -> f64 {
        let n = self.air_tx_attempts;
        if n == 0 {
            1.0
        } else {
            self.air_tx_ok as f64 / n as f64
        }
    }

    fn record_drop(&mut self, reason: DropReason) {
        match reason {
            DropReason::Offline => self.dropped_offline += 1,
            DropReason::OutOfRange => self.dropped_out_of_range += 1,
            DropReason::AirQueueFull => self.dropped_air_queue_full += 1,
            DropReason::ThroughputLimited => self.dropped_throughput_limited += 1,
            DropReason::InboxFull => self.dropped_inbox_full += 1,
            DropReason::RouteTableFull => self.dropped_route_table_full += 1,
            DropReason::NoRoute => self.dropped_no_route += 1,
            DropReason::HopLimit => self.dropped_hop_limit += 1,
        }
    }
}

/// Aggregated view for comparing runs while sweeping bandwidth, memory, and node count.
#[derive(Debug, Clone, PartialEq)]
pub struct StabilityMetrics {
    pub drops_per_tick: f64,
    pub resource_drops_per_tick: f64,
    pub throughput_drops_per_tick: f64,
    pub air_tx_success_ratio: f64,
    pub data_delivery_ratio: Option<f64>,
    pub avg_route_table_utilization: f64,
    pub max_air_queue_depth: usize,
    pub max_inbox_depth: usize,
}

impl StabilityMetrics {
    pub fn from_sim(sim: &MeshSim) -> Self {
        let ticks = sim.stats.ticks.max(1) as f64;
        let dropped_total = sim.stats.dropped_total() as f64;
        let resource = sim.stats.dropped_resource_pressure() as f64;
        let throughput = sim.stats.dropped_throughput_limited as f64;
        let data_delivery_ratio = if sim.stats.data_sent > 0 {
            Some(sim.stats.data_delivered as f64 / sim.stats.data_sent as f64)
        } else {
            None
        };
        Self {
            drops_per_tick: dropped_total / ticks,
            resource_drops_per_tick: resource / ticks,
            throughput_drops_per_tick: throughput / ticks,
            air_tx_success_ratio: sim.stats.air_tx_success_ratio(),
            data_delivery_ratio,
            avg_route_table_utilization: sim.avg_route_table_utilization(),
            max_air_queue_depth: sim.stats.max_air_queue_depth,
            max_inbox_depth: sim.stats.max_inbox_depth,
        }
    }
}

/// Memory limits that apply uniformly to every node in a benchmark run.
#[derive(Debug, Clone)]
pub struct MeshMemoryBudget {
    pub inbox_limit: usize,
    pub route_table_limit: usize,
    pub air_queue_limit: usize,
}

impl Default for MeshMemoryBudget {
    fn default() -> Self {
        Self {
            inbox_limit: 64,
            route_table_limit: 256,
            air_queue_limit: 4096,
        }
    }
}

/// Processing and announce rates that approximate “bandwidth” and CPU budget in this coarse sim.
#[derive(Debug, Clone)]
pub struct MeshBandwidthBudget {
    pub packets_per_tick: usize,
    pub latency_ticks: Tick,
    pub announce_interval: Tick,
}

impl Default for MeshBandwidthBudget {
    fn default() -> Self {
        Self {
            packets_per_tick: 8,
            latency_ticks: 1,
            announce_interval: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkParams {
    pub nodes: usize,
    pub ticks: Tick,
    pub radio_range: f32,
    /// Distance between consecutive nodes on a straight-line topology.
    pub spacing: f32,
    pub memory: MeshMemoryBudget,
    pub bandwidth: MeshBandwidthBudget,
    /// Gross medium bitrate (bit/s). `None` = no throughput limit.
    pub medium_throughput_bps: Option<u64>,
    /// Microseconds of simulated time per tick (see [`SimConfig::tick_duration_us`]).
    pub tick_duration_us: u64,
    /// Optional bit-bucket cap (see [`SimConfig::medium_bit_bucket_max`]).
    pub medium_bit_bucket_max: Option<u64>,
    /// Spread announce deadlines across the interval (see [`SimConfig::stagger_announces`]).
    pub stagger_announces: bool,
    /// Short MAC airtime for PHY budgeting (see [`SimConfig::medium_on_air_bytes_override`]).
    pub medium_on_air_bytes_override: Option<usize>,
}

impl Default for BenchmarkParams {
    fn default() -> Self {
        Self {
            nodes: 32,
            ticks: 64,
            radio_range: 1_000.0,
            spacing: 1.0,
            memory: MeshMemoryBudget::default(),
            bandwidth: MeshBandwidthBudget::default(),
            medium_throughput_bps: None,
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkReport {
    pub params: BenchmarkParams,
    pub stats: SimStats,
    pub stability: StabilityMetrics,
}

/// Run a line topology with uniform node settings; intended for parameter sweeps and benches.
pub fn run_line_announce_benchmark(params: &BenchmarkParams) -> BenchmarkReport {
    let mut sim = MeshSim::new(SimConfig {
        radio: RadioConfig {
            range: params.radio_range,
            latency_ticks: params.bandwidth.latency_ticks,
            air_queue_limit: params.memory.air_queue_limit,
        },
        medium_throughput_bps: params.medium_throughput_bps,
        tick_duration_us: params.tick_duration_us,
        medium_bit_bucket_max: params.medium_bit_bucket_max,
        stagger_announces: params.stagger_announces,
        medium_on_air_bytes_override: params.medium_on_air_bytes_override,
        ..SimConfig::default()
    });

    let node_cfg = NodeConfig {
        inbox_limit: params.memory.inbox_limit,
        route_table_limit: params.memory.route_table_limit.max(1),
        packets_per_tick: params.bandwidth.packets_per_tick,
        announce_interval: params.bandwidth.announce_interval,
    };

    for id in 0..params.nodes {
        sim.add_node(
            Position {
                x: id as f32 * params.spacing,
                y: 0.0,
            },
            node_cfg.clone(),
        );
    }

    sim.run_ticks(params.ticks);
    let stability = StabilityMetrics::from_sim(&sim);
    BenchmarkReport {
        params: params.clone(),
        stats: sim.stats.clone(),
        stability,
    }
}

// --- LoRa-class “realistic enough for MeshSim” presets -------------------------------------------

/// Gross PHY bitrate used in [`lora_realistic_line_benchmark`] (matches `lora_sweep` / `rf_compare` class).
pub const LORA_CLASS_BITRATE_BPS: u64 = 10_000;

/// Simulated tick duration for [`lora_realistic_line_benchmark`]: **50 ms** per tick (LoRa airtime + MCU quantised time).
pub const LORA_CLASS_TICK_US: u64 = 50_000;

/// On-air bytes debited per frame for medium budgeting (short MAC / SF-class framing, not full logical announce size).
pub const LORA_CLASS_ON_AIR_BYTES: usize = 12;

/// Line topology spacing for LoRa presets in this crate (**meters**).
pub const LORA_LINE_SPACING_M: f32 = 45.0;

/// One-hop nominal range for LoRa presets (**meters**): ~2–3 line neighbors at [`LORA_LINE_SPACING_M`].
pub const LORA_LINE_RANGE_M: f32 = 130.0;

/// Ticks between periodic announces per node in [`lora_realistic_line_benchmark`] (`300` × 50 ms ≈ **15 s** simulated time).
pub const LORA_LINE_ANNOUNCE_INTERVAL_TICKS: Tick = 300;

/// Build [`BenchmarkParams`] for a **calibrated** LoRa-class line: bitrate-limited medium, staggered announces,
/// short on-air debit — same knobs as the calibrated **B)** branch in `src/bin/lora_sweep.rs`.
///
/// This is still [`MeshSim`] semantics (toy routing from direct announces), but the **RF budget and cadence**
/// are meant to resemble constrained LoRa control-plane load, not infinite Wi-Fi.
#[must_use]
pub fn lora_realistic_line_params(nodes: usize, ticks: Tick) -> BenchmarkParams {
    BenchmarkParams {
        nodes,
        ticks,
        radio_range: LORA_LINE_RANGE_M,
        spacing: LORA_LINE_SPACING_M,
        memory: MeshMemoryBudget {
            inbox_limit: 512,
            route_table_limit: nodes.max(1),
            air_queue_limit: 250_000,
        },
        bandwidth: MeshBandwidthBudget {
            packets_per_tick: 64,
            latency_ticks: 1,
            announce_interval: LORA_LINE_ANNOUNCE_INTERVAL_TICKS,
        },
        medium_throughput_bps: Some(LORA_CLASS_BITRATE_BPS),
        tick_duration_us: LORA_CLASS_TICK_US,
        medium_bit_bucket_max: Some(200_000),
        stagger_announces: true,
        medium_on_air_bytes_override: Some(LORA_CLASS_ON_AIR_BYTES),
    }
}

/// Run [`run_line_announce_benchmark`] with [`lora_realistic_line_params`] (`nodes` ≥ 1).
#[must_use]
pub fn lora_realistic_line_benchmark(nodes: usize, ticks: Tick) -> BenchmarkReport {
    assert!(nodes >= 1, "nodes must be >= 1");
    let p = lora_realistic_line_params(nodes, ticks);
    run_line_announce_benchmark(&p)
}

/// Convenience: **100 nodes** on the LoRa line (see [`lora_realistic_line_benchmark`]).
#[must_use]
pub fn lora_realistic_100_node_line_benchmark(ticks: Tick) -> BenchmarkReport {
    lora_realistic_line_benchmark(100, ticks)
}

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: AddressHash,
    next_hop: NodeId,
    learned_at: Tick,
}

#[derive(Debug, Clone)]
struct Frame {
    previous_hop: NodeId,
    packet: Arc<Packet>,
}

#[derive(Debug, Clone)]
struct ScheduledFrame {
    deliver_at: Tick,
    recipient: NodeId,
    frame: Frame,
}

#[derive(Debug)]
pub struct SimNode {
    id: NodeId,
    address: AddressHash,
    position: Position,
    online: bool,
    config: NodeConfig,
    inbox: VecDeque<Frame>,
    routes: VecDeque<RouteEntry>,
    next_announce_at: Tick,
}

impl SimNode {
    fn new(id: NodeId, position: Position, config: NodeConfig, next_announce_at: Tick) -> Self {
        Self {
            id,
            address: AddressHash::new_from_slice(&id.to_le_bytes()),
            position,
            online: true,
            config,
            inbox: VecDeque::new(),
            routes: VecDeque::new(),
            next_announce_at,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn address(&self) -> AddressHash {
        self.address
    }

    pub fn position(&self) -> Position {
        self.position
    }

    pub fn online(&self) -> bool {
        self.online
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn knows_route_to(&self, destination: AddressHash) -> bool {
        self.routes
            .iter()
            .any(|entry| entry.destination == destination)
    }

    fn enqueue(&mut self, frame: Frame) -> Result<(), DropReason> {
        if !self.online {
            return Err(DropReason::Offline);
        }
        if self.inbox.len() >= self.config.inbox_limit {
            return Err(DropReason::InboxFull);
        }
        self.inbox.push_back(frame);
        Ok(())
    }

    fn learn_route(
        &mut self,
        destination: AddressHash,
        next_hop: NodeId,
        tick: Tick,
    ) -> Result<(), DropReason> {
        if destination == self.address {
            return Ok(());
        }
        if let Some(route) = self
            .routes
            .iter_mut()
            .find(|entry| entry.destination == destination)
        {
            route.next_hop = next_hop;
            route.learned_at = tick;
            return Ok(());
        }
        if self.routes.len() >= self.config.route_table_limit {
            return Err(DropReason::RouteTableFull);
        }
        self.routes.push_back(RouteEntry {
            destination,
            next_hop,
            learned_at: tick,
        });
        Ok(())
    }

    fn next_hop_for(&self, destination: AddressHash) -> Option<NodeId> {
        self.routes
            .iter()
            .find(|entry| entry.destination == destination)
            .map(|entry| entry.next_hop)
    }
}

#[derive(Debug)]
pub struct MeshSim {
    config: SimConfig,
    nodes: Vec<SimNode>,
    air: VecDeque<ScheduledFrame>,
    stats: SimStats,
    tick: Tick,
    /// Uniform grid for neighbor queries (`broadcast_from`). Rebuilt at each [`MeshSim::step`] start.
    spatial_buckets: HashMap<(i32, i32), Vec<NodeId>>,
    spatial_cell_size: f32,
    /// Chebyshev radius in cells around the source cell to scan (covers all pairs within `radio.range`).
    spatial_dr: i32,
    /// Bits still transmissible on the shared medium for the current tick (reset in [`MeshSim::step`]).
    medium_bits_remaining: u64,
}

impl MeshSim {
    pub fn new(config: SimConfig) -> Self {
        Self {
            config,
            nodes: Vec::new(),
            air: VecDeque::new(),
            stats: SimStats::default(),
            tick: 0,
            spatial_buckets: HashMap::new(),
            spatial_cell_size: 1.0,
            spatial_dr: 1,
            medium_bits_remaining: 0,
        }
    }

    pub fn add_node(&mut self, position: Position, config: NodeConfig) -> NodeId {
        let id = self.nodes.len();
        let next_announce_at = if self.config.stagger_announces {
            let iv = config.announce_interval.max(1);
            (id as Tick).wrapping_mul(17) % iv
        } else {
            0
        };
        self.nodes.push(SimNode::new(id, position, config, next_announce_at));
        id
    }

    pub fn node(&self, id: NodeId) -> &SimNode {
        &self.nodes[id]
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut SimNode {
        &mut self.nodes[id]
    }

    pub fn set_position(&mut self, id: NodeId, position: Position) {
        self.nodes[id].position = position;
    }

    pub fn set_online(&mut self, id: NodeId, online: bool) {
        self.nodes[id].online = online;
    }

    pub fn stats(&self) -> &SimStats {
        &self.stats
    }

    pub fn tick(&self) -> Tick {
        self.tick
    }

    /// Average of `route_count / route_table_limit` across online nodes (0..=1).
    pub fn avg_route_table_utilization(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        let mut sum = 0.0;
        let mut n = 0usize;
        for node in &self.nodes {
            if !node.online {
                continue;
            }
            let cap = node.config.route_table_limit.max(1) as f64;
            sum += node.route_count() as f64 / cap;
            n += 1;
        }
        if n == 0 {
            0.0
        } else {
            sum / n as f64
        }
    }

    pub fn send_data(
        &mut self,
        source: NodeId,
        destination: AddressHash,
        payload: &[u8],
    ) -> Result<(), DropReason> {
        if !self.nodes[source].online {
            self.stats.record_drop(DropReason::Offline);
            return Err(DropReason::Offline);
        }

        let packet = data_packet(destination, payload);
        let frame = Frame {
            previous_hop: source,
            packet,
        };

        self.stats.data_sent += 1;
        self.broadcast_from(source, frame)
    }

    fn rebuild_spatial_index(&mut self) {
        self.spatial_buckets.clear();
        let range = self.config.radio.range.max(0.0).max(1e-6);
        // Cell size ties to range so a 2D grid sweep cannot miss in-range pairs.
        let cell_size = (range / 2.0).max(1e-4);
        let dr = ((range / cell_size).ceil() as i32 + 2).max(1);
        self.spatial_cell_size = cell_size;
        self.spatial_dr = dr;

        for id in 0..self.nodes.len() {
            let p = self.nodes[id].position;
            let cx = (p.x / cell_size).floor() as i32;
            let cy = (p.y / cell_size).floor() as i32;
            self.spatial_buckets.entry((cx, cy)).or_default().push(id);
        }
    }

    pub fn step(&mut self) {
        self.rebuild_spatial_index();
        self.medium_bits_remaining = match self.config.medium_throughput_bps {
            Some(bps) => {
                let grant = medium_bits_per_tick(bps, self.config.tick_duration_us);
                match self.config.medium_bit_bucket_max {
                    None => grant,
                    Some(cap) => self
                        .medium_bits_remaining
                        .saturating_add(grant)
                        .min(cap),
                }
            }
            None => u64::MAX,
        };
        self.emit_due_announces();
        self.deliver_due_air_frames();
        self.process_node_inboxes();
        self.tick += 1;
        self.stats.ticks = self.tick;
        self.stats.max_air_queue_depth = self.stats.max_air_queue_depth.max(self.air.len());
    }

    pub fn run_ticks(&mut self, ticks: Tick) {
        for _ in 0..ticks {
            self.step();
        }
    }

    fn emit_due_announces(&mut self) {
        for id in 0..self.nodes.len() {
            if !self.nodes[id].online {
                continue;
            }
            if self.tick < self.nodes[id].next_announce_at {
                continue;
            }

            let announce_interval = self.nodes[id].config.announce_interval.max(1);
            self.nodes[id].next_announce_at = self.tick + announce_interval;
            let packet = announce_packet(self.nodes[id].address);
            let frame = Frame {
                previous_hop: id,
                packet,
            };
            self.stats.announces_sent += 1;
            let _ = self.broadcast_from(id, frame);
        }
    }

    fn deliver_due_air_frames(&mut self) {
        let mut remaining = VecDeque::new();
        while let Some(scheduled) = self.air.pop_front() {
            if scheduled.deliver_at > self.tick {
                remaining.push_back(scheduled);
                continue;
            }
            match self.nodes[scheduled.recipient].enqueue(scheduled.frame) {
                Ok(()) => {
                    self.stats.max_inbox_depth = self
                        .stats
                        .max_inbox_depth
                        .max(self.nodes[scheduled.recipient].inbox.len());
                }
                Err(reason) => self.stats.record_drop(reason),
            }
        }
        self.air = remaining;
    }

    fn process_node_inboxes(&mut self) {
        for node_id in 0..self.nodes.len() {
            if !self.nodes[node_id].online {
                continue;
            }

            let budget = self.nodes[node_id].config.packets_per_tick;
            for _ in 0..budget {
                let Some(frame) = self.nodes[node_id].inbox.pop_front() else {
                    break;
                };
                self.handle_frame(node_id, frame);
            }
        }
    }

    fn handle_frame(&mut self, node_id: NodeId, frame: Frame) {
        let destination = frame.packet.destination;
        match frame.packet.header.packet_type {
            PacketType::Announce => {
                self.stats.announces_received += 1;
                if let Err(reason) =
                    self.nodes[node_id].learn_route(destination, frame.previous_hop, self.tick)
                {
                    self.stats.record_drop(reason);
                }
            }
            PacketType::Data if destination == self.nodes[node_id].address => {
                self.stats.data_delivered += 1;
            }
            PacketType::Data => {
                let Some(next_hop) = self.nodes[node_id].next_hop_for(destination) else {
                    self.stats.record_drop(DropReason::NoRoute);
                    return;
                };
                if frame.packet.header.hops >= self.config.max_packet_hops {
                    self.stats.record_drop(DropReason::HopLimit);
                    return;
                }
                let mut pkt = *frame.packet;
                pkt.header.hops += 1;
                let forwarded = Frame {
                    previous_hop: node_id,
                    packet: Arc::new(pkt),
                };
                self.stats.data_forwarded += 1;
                let _ = self.unicast_from(node_id, next_hop, forwarded);
            }
            _ => {}
        }
    }

    fn broadcast_from(&mut self, source: NodeId, frame: Frame) -> Result<(), DropReason> {
        let mut delivered_any = false;
        let pos = self.nodes[source].position;
        let cell = self.spatial_cell_size;
        let cx = (pos.x / cell).floor() as i32;
        let cy = (pos.y / cell).floor() as i32;
        let dr = self.spatial_dr;
        let range = self.config.radio.range;
        let prev = frame.previous_hop;
        let src_pos = self.nodes[source].position;

        for ix in -dr..=dr {
            for iy in -dr..=dr {
                let Some(bucket) = self.spatial_buckets.get(&(cx + ix, cy + iy)) else {
                    continue;
                };
                let recipients = bucket.clone();
                for recipient in recipients {
                    if recipient == source || recipient == prev {
                        continue;
                    }
                    if !self.nodes[recipient].online {
                        continue;
                    }
                    if src_pos.distance_to(self.nodes[recipient].position) > range {
                        continue;
                    }
                    match self.schedule_air_delivery(
                        source,
                        recipient,
                        Frame {
                            previous_hop: frame.previous_hop,
                            packet: Arc::clone(&frame.packet),
                        },
                    ) {
                        Ok(()) => delivered_any = true,
                        Err(DropReason::OutOfRange) => {}
                        Err(DropReason::ThroughputLimited) => {
                            self.stats.record_drop(DropReason::ThroughputLimited);
                        }
                        Err(reason) => {
                            self.stats.record_drop(reason);
                            return Err(reason);
                        }
                    }
                }
            }
        }
        if delivered_any {
            Ok(())
        } else {
            self.stats.record_drop(DropReason::OutOfRange);
            Err(DropReason::OutOfRange)
        }
    }

    fn unicast_from(
        &mut self,
        source: NodeId,
        recipient: NodeId,
        frame: Frame,
    ) -> Result<(), DropReason> {
        match self.schedule_air_delivery(source, recipient, frame) {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.stats.record_drop(reason);
                Err(reason)
            }
        }
    }

    fn schedule_air_delivery(
        &mut self,
        source: NodeId,
        recipient: NodeId,
        mut frame: Frame,
    ) -> Result<(), DropReason> {
        self.stats.air_tx_attempts += 1;
        if !self.nodes[source].online || !self.nodes[recipient].online {
            return Err(DropReason::Offline);
        }
        if self.nodes[source]
            .position
            .distance_to(self.nodes[recipient].position)
            > self.config.radio.range
        {
            return Err(DropReason::OutOfRange);
        }
        if self.air.len() >= self.config.radio.air_queue_limit {
            return Err(DropReason::AirQueueFull);
        }

        if self.config.medium_throughput_bps.is_some() {
            let bytes = self
                .config
                .medium_on_air_bytes_override
                .unwrap_or_else(|| approx_packet_on_air_bytes(frame.packet.as_ref()));
            let bits = (bytes as u64).saturating_mul(8).max(8);
            if bits > self.medium_bits_remaining {
                return Err(DropReason::ThroughputLimited);
            }
            self.medium_bits_remaining -= bits;
        }

        frame.previous_hop = source;
        self.air.push_back(ScheduledFrame {
            deliver_at: self.tick + self.config.radio.latency_ticks,
            recipient,
            frame,
        });
        self.stats.air_tx_ok += 1;
        self.stats.max_air_queue_depth = self.stats.max_air_queue_depth.max(self.air.len());
        Ok(())
    }
}

fn announce_packet(destination: AddressHash) -> Arc<Packet> {
    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Announce;
    packet.destination = destination;
    Arc::new(packet)
}

fn data_packet(destination: AddressHash, payload: &[u8]) -> Arc<Packet> {
    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Data;
    packet.destination = destination;
    packet.data = PacketDataBuffer::new_from_slice(payload);
    Arc::new(packet)
}

#[derive(Debug, Clone)]
pub struct ScenarioReport {
    pub name: &'static str,
    pub stats: SimStats,
}

pub fn run_dense_announce_pressure_scenario(nodes: usize, ticks: Tick) -> ScenarioReport {
    let report = run_line_announce_benchmark(&BenchmarkParams {
        nodes,
        ticks,
        radio_range: 1_000.0,
        spacing: 1.0,
        memory: MeshMemoryBudget {
            inbox_limit: 8,
            route_table_limit: nodes.max(1),
            air_queue_limit: 64,
        },
        bandwidth: MeshBandwidthBudget {
            packets_per_tick: 2,
            latency_ticks: 1,
            announce_interval: 1,
        },
        medium_throughput_bps: None,
        tick_duration_us: 1_000,
        medium_bit_bucket_max: None,
        stagger_announces: false,
        medium_on_air_bytes_override: None,
    });
    ScenarioReport {
        name: "dense_announce_pressure",
        stats: report.stats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_config() -> NodeConfig {
        NodeConfig {
            announce_interval: 3,
            ..NodeConfig::default()
        }
    }

    #[test]
    fn two_nodes_learn_routes_from_regular_announces() {
        let mut sim = MeshSim::new(SimConfig::default());
        let a = sim.add_node(Position { x: 0.0, y: 0.0 }, node_config());
        let b = sim.add_node(Position { x: 10.0, y: 0.0 }, node_config());

        sim.run_ticks(4);

        assert!(sim.node(a).knows_route_to(sim.node(b).address()));
        assert!(sim.node(b).knows_route_to(sim.node(a).address()));
        assert!(sim.stats().announces_received >= 2);
    }

    #[test]
    fn relay_forwards_data_across_three_node_line() {
        let mut sim = MeshSim::new(SimConfig {
            radio: RadioConfig {
                range: 60.0,
                latency_ticks: 1,
                air_queue_limit: 128,
            },
            ..SimConfig::default()
        });
        let a = sim.add_node(Position { x: 0.0, y: 0.0 }, node_config());
        let b = sim.add_node(Position { x: 50.0, y: 0.0 }, node_config());
        let c = sim.add_node(Position { x: 100.0, y: 0.0 }, node_config());

        sim.run_ticks(4);
        assert!(sim.node(b).knows_route_to(sim.node(c).address()));

        sim.send_data(a, sim.node(c).address(), b"hello").unwrap();
        sim.run_ticks(4);

        assert_eq!(sim.stats().data_delivered, 1);
        assert!(sim.stats().data_forwarded >= 1);
    }

    #[test]
    fn movement_breaks_and_restores_connectivity() {
        let mut sim = MeshSim::new(SimConfig {
            radio: RadioConfig {
                range: 25.0,
                latency_ticks: 1,
                air_queue_limit: 64,
            },
            ..SimConfig::default()
        });
        let a = sim.add_node(Position { x: 0.0, y: 0.0 }, node_config());
        let b = sim.add_node(Position { x: 10.0, y: 0.0 }, node_config());

        sim.run_ticks(3);
        assert!(sim.node(a).knows_route_to(sim.node(b).address()));

        sim.set_position(b, Position { x: 200.0, y: 0.0 });
        assert_eq!(
            sim.send_data(a, sim.node(b).address(), b"too far"),
            Err(DropReason::OutOfRange)
        );

        sim.set_position(b, Position { x: 10.0, y: 0.0 });
        sim.send_data(a, sim.node(b).address(), b"back").unwrap();
        sim.run_ticks(2);

        assert_eq!(sim.stats().data_delivered, 1);
    }

    #[test]
    fn dense_announce_pressure_reports_clogging() {
        let report = run_dense_announce_pressure_scenario(32, 8);

        assert!(report.stats.is_clogged());
        assert!(report.stats.dropped_air_queue_full > 0 || report.stats.dropped_inbox_full > 0);
        assert!(report.stats.max_air_queue_depth > 0);
    }

    #[test]
    fn benchmark_report_tracks_air_success_and_resource_drops() {
        let loose = run_line_announce_benchmark(&BenchmarkParams {
            nodes: 24,
            ticks: 24,
            radio_range: 1_000.0,
            spacing: 1.0,
            memory: MeshMemoryBudget {
                inbox_limit: 128,
                route_table_limit: 24,
                air_queue_limit: 8192,
            },
            bandwidth: MeshBandwidthBudget {
                packets_per_tick: 16,
                latency_ticks: 1,
                announce_interval: 1,
            },
            medium_throughput_bps: None,
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        });
        let tight = run_line_announce_benchmark(&BenchmarkParams {
            nodes: 24,
            ticks: 24,
            radio_range: 1_000.0,
            spacing: 1.0,
            memory: MeshMemoryBudget {
                inbox_limit: 4,
                route_table_limit: 24,
                air_queue_limit: 32,
            },
            bandwidth: MeshBandwidthBudget {
                packets_per_tick: 1,
                latency_ticks: 1,
                announce_interval: 1,
            },
            medium_throughput_bps: None,
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        });

        assert!(loose.stats.air_tx_attempts > 0);
        assert!(tight.stats.dropped_resource_pressure() > 0);
        assert!(loose.stability.air_tx_success_ratio > tight.stability.air_tx_success_ratio);
    }

    /// Large regression; run with `cargo test -p reticulum-mesh-sim ten_k_nodes_line_smoke -- --ignored --release`.
    #[test]
    #[ignore]
    fn ten_k_nodes_line_smoke() {
        let report = run_line_announce_benchmark(&BenchmarkParams {
            nodes: 10_000,
            ticks: 3,
            radio_range: 1_000.0,
            spacing: 1.0,
            memory: MeshMemoryBudget {
                inbox_limit: 32,
                route_table_limit: 256,
                air_queue_limit: 16_384,
            },
            bandwidth: MeshBandwidthBudget {
                packets_per_tick: 8,
                latency_ticks: 1,
                announce_interval: 500,
            },
            medium_throughput_bps: None,
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        });
        assert_eq!(report.stats.ticks, 3);
        assert!(report.stats.air_tx_attempts > 0);
    }

    #[test]
    fn low_bitrate_marks_throughput_drops() {
        let narrow = run_line_announce_benchmark(&BenchmarkParams {
            nodes: 16,
            ticks: 50,
            radio_range: 500.0,
            spacing: 25.0,
            memory: MeshMemoryBudget {
                inbox_limit: 256,
                route_table_limit: 32,
                air_queue_limit: 50_000,
            },
            bandwidth: MeshBandwidthBudget {
                packets_per_tick: 32,
                latency_ticks: 1,
                announce_interval: 2,
            },
            medium_throughput_bps: Some(15_000),
            tick_duration_us: 1_000,
            medium_bit_bucket_max: None,
            stagger_announces: false,
            medium_on_air_bytes_override: None,
        });
        assert!(
            narrow.stats.dropped_throughput_limited > 0,
            "expected PHY budget to block most parallel air copies"
        );
        assert!(narrow.stability.throughput_drops_per_tick > 0.0);
    }

    #[test]
    fn two_node_lora_with_bit_bucket_learns_routes() {
        let mut sim = MeshSim::new(SimConfig {
            radio: RadioConfig {
                range: 120.0,
                latency_ticks: 1,
                air_queue_limit: 256,
            },
            medium_throughput_bps: Some(10_000),
            tick_duration_us: 10_000,
            medium_bit_bucket_max: Some(50_000),
            ..SimConfig::default()
        });
        let cfg = NodeConfig {
            announce_interval: 20,
            packets_per_tick: 32,
            ..NodeConfig::default()
        };
        let a = sim.add_node(Position { x: 0.0, y: 0.0 }, cfg.clone());
        let b = sim.add_node(Position { x: 40.0, y: 0.0 }, cfg);
        sim.run_ticks(200);
        assert!(sim.node(a).knows_route_to(sim.node(b).address()));
        assert!(sim.node(b).knows_route_to(sim.node(a).address()));
        assert!(sim.stats().announces_received >= 2);
    }
}
