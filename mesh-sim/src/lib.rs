//! Large-scale host-side mesh simulator for reticulum-rs.
//!
//! This crate is intentionally separate from the core `reticulum` crate. The
//! simulator models virtual radio conditions around Reticulum packet boundaries
//! instead of reimplementing core protocol policy in the main crate.
//!
//! For experiments over node count, buffer sizes, and processing budget, see
//! [`BenchmarkParams`], [`run_line_announce_benchmark`], and [`StabilityMetrics`].
//! Run `cargo bench -p reticulum-mesh-sim --bench mesh_stress` for Criterion timing.

use std::collections::VecDeque;

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
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            radio: RadioConfig::default(),
            max_packet_hops: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Offline,
    OutOfRange,
    AirQueueFull,
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
            + self.dropped_inbox_full
            + self.dropped_route_table_full
            + self.dropped_no_route
            + self.dropped_hop_limit
    }

    /// Drops tied to finite buffers or routing tables (typical “stability under load” signals).
    pub fn dropped_resource_pressure(&self) -> u64 {
        self.dropped_air_queue_full + self.dropped_inbox_full + self.dropped_route_table_full
    }

    pub fn is_clogged(&self) -> bool {
        self.dropped_air_queue_full > 0 || self.dropped_inbox_full > 0
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
        let data_delivery_ratio = if sim.stats.data_sent > 0 {
            Some(sim.stats.data_delivered as f64 / sim.stats.data_sent as f64)
        } else {
            None
        };
        Self {
            drops_per_tick: dropped_total / ticks,
            resource_drops_per_tick: resource / ticks,
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

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: AddressHash,
    next_hop: NodeId,
    learned_at: Tick,
}

#[derive(Debug, Clone)]
struct Frame {
    previous_hop: NodeId,
    packet: Packet,
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
    fn new(id: NodeId, position: Position, config: NodeConfig) -> Self {
        Self {
            id,
            address: AddressHash::new_from_slice(format!("mesh-sim-node-{id}").as_bytes()),
            position,
            online: true,
            config,
            inbox: VecDeque::new(),
            routes: VecDeque::new(),
            next_announce_at: 0,
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
}

impl MeshSim {
    pub fn new(config: SimConfig) -> Self {
        Self {
            config,
            nodes: Vec::new(),
            air: VecDeque::new(),
            stats: SimStats::default(),
            tick: 0,
        }
    }

    pub fn add_node(&mut self, position: Position, config: NodeConfig) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(SimNode::new(id, position, config));
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

    pub fn step(&mut self) {
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
                let mut forwarded = frame;
                forwarded.previous_hop = node_id;
                forwarded.packet.header.hops += 1;
                self.stats.data_forwarded += 1;
                let _ = self.unicast_from(node_id, next_hop, forwarded);
            }
            _ => {}
        }
    }

    fn broadcast_from(&mut self, source: NodeId, frame: Frame) -> Result<(), DropReason> {
        let mut delivered_any = false;
        for recipient in 0..self.nodes.len() {
            if recipient == source {
                continue;
            }
            if frame.previous_hop == recipient {
                continue;
            }
            match self.schedule_air_delivery(source, recipient, frame.clone()) {
                Ok(()) => delivered_any = true,
                Err(DropReason::OutOfRange) => {}
                Err(reason) => {
                    self.stats.record_drop(reason);
                    return Err(reason);
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

fn announce_packet(destination: AddressHash) -> Packet {
    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Announce;
    packet.destination = destination;
    packet
}

fn data_packet(destination: AddressHash, payload: &[u8]) -> Packet {
    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Data;
    packet.destination = destination;
    packet.data = PacketDataBuffer::new_from_slice(payload);
    packet
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
        });

        assert!(loose.stats.air_tx_attempts > 0);
        assert!(tight.stats.dropped_resource_pressure() > 0);
        assert!(loose.stability.air_tx_success_ratio > tight.stability.air_tx_success_ratio);
    }
}
