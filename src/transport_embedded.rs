//! Stage D embedded transport runner skeleton.
//!
//! This module is intentionally minimal: it provides an embedded/no-std execution
//! seam for interface ingress/egress without depending on Tokio or std transport.
//! Later Stage D steps can move selected transport execution paths here.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::async_backend::{broadcast, spawn, CancellationToken};
use crate::hash::AddressHash;
use crate::iface_messages::{RxMessage, TxMessage, TxMessageType};
use crate::packet::{DestinationType, Packet, PacketDataBuffer, PacketType};
use crate::transport_engine::{
    build_packet_forward_type2, build_path_request_decision_input, decide_duplicate_outcome,
    decide_ingress_from_input, decide_intermediate_link_request_action,
    decide_link_lifecycle_transition, decide_link_request_route,
    decide_path_request_action_from_input, decide_proof_handle_followup, decide_single_data_route,
    decide_staged_path_request_egress, intermediate_link_table_apply_proof,
    intermediate_link_table_handle_keepalive, is_in_link_pending_proof, is_path_request_packet,
    link_request_destination_requests_proof, lookup_path_request_state, path_cache_lookup_next_hop,
    path_request_fixed_destination, should_consider_in_link_pending_proof,
    should_handle_fixed_destination_path_request, should_handle_keepalive_response,
    try_register_intermediate_link_entry, IngressAction, IngressDecision, IngressDecisionInput,
    IntermediateLinkEntry, IntermediateLinkRequestAction, LinkLifecycleTransition,
    LinkRequestRoute, PathRequestAction, ProofHandleFollowup, SingleDataRoute,
    StagedPathRequestEgressDecision, STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD,
};

/// Queue a Type2 forward on `egress_tx`, matching std `PathTable::handle_inbound_packet` + `Direct(iface)`.
fn queue_path_table_forward(
    egress_tx: &broadcast::Sender<TxMessage>,
    egress_generated_count: &Arc<AtomicU32>,
    egress_dropped_count: &Arc<AtomicU32>,
    packet: &Packet,
    next_hop: AddressHash,
    ingress_iface: AddressHash,
) -> bool {
    if ingress_iface == AddressHash::new_empty() {
        return false;
    }
    let out = build_packet_forward_type2(packet, next_hop);
    queue_prepared_direct(
        egress_tx,
        egress_generated_count,
        egress_dropped_count,
        out,
        ingress_iface,
    )
}

fn queue_prepared_direct(
    egress_tx: &broadcast::Sender<TxMessage>,
    egress_generated_count: &Arc<AtomicU32>,
    egress_dropped_count: &Arc<AtomicU32>,
    packet: Packet,
    iface: AddressHash,
) -> bool {
    if iface == AddressHash::new_empty() {
        return false;
    }
    if egress_tx
        .send(TxMessage {
            tx_type: TxMessageType::Direct(iface),
            packet,
        })
        .is_ok()
    {
        egress_generated_count.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        egress_dropped_count.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Tiny typed command channel for Stage D runner behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedCommand {
    /// Request that the runner emits a small egress probe packet.
    EmitProbe { destination: AddressHash },
    /// Enable/disable automatic probe emission when announce ingress is observed.
    SetAutoProbeOnIngressAnnounce(bool),
    /// Emit a synthetic packet with explicit packet type/payload for staged runner validation.
    EmitSynthetic {
        packet_type: PacketType,
        destination: AddressHash,
        payload: &'static [u8],
    },
    /// Emit a synthetic packet with runtime-owned payload bytes.
    EmitSyntheticBytes {
        packet_type: PacketType,
        destination: AddressHash,
        payload: PacketDataBuffer,
    },
}

/// Tiny typed event channel for Stage D runner observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedEvent {
    IngressClassified {
        source: EmbeddedIngressSource,
        packet_type: PacketType,
        destination: AddressHash,
    },
    EgressGenerated {
        destination: AddressHash,
        bytes: usize,
    },
    /// Explicit Stage D signal for board tests:
    /// announce ingress produced a path-request-shaped egress packet.
    AnnounceTriggeredPathRequest {
        destination: AddressHash,
        bytes: usize,
    },
    AutoProbeOnIngressChanged(bool),
    SyntheticEgressRequested {
        packet_type: PacketType,
        destination: AddressHash,
        bytes: usize,
    },
    LinkLifecyclePending {
        destination: AddressHash,
    },
    LinkLifecycleActivated {
        destination: AddressHash,
    },
    /// Non-path-request `Data` classified with shared std policy (`decide_single_data_route`).
    ///
    /// `source` is the interface-origin address on the ingress message (empty for synthetic injects).
    ///
    /// `forward_queued` mirrors std `send_to_next_hop` when a Type2 packet was queued for egress.
    DataRouted {
        route: SingleDataRoute,
        destination: AddressHash,
        source: AddressHash,
        forward_queued: bool,
    },
    /// Link-request routing outcome (std `handle_link_request` branches).
    LinkRequestRouted {
        route: LinkRequestRoute,
        destination: AddressHash,
        source: AddressHash,
        /// True when intermediate forward matched std `handle_link_request_as_intermediate` egress.
        forward_queued: bool,
        /// True when a new row was inserted into the intermediate link table (std `LinkTable::add`).
        link_table_inserted: bool,
    },
}

/// Where an ingress message came from in Stage D.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedIngressSource {
    /// Packet came from an actual interface/driver path (for example HaLow RX).
    Interface,
    /// Packet was injected by Stage D synthetic stimulation helpers.
    Synthetic,
}

/// Minimal embedded transport config for Stage D skeleton.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedTransportConfig {
    /// Queue capacity used for ingress/egress/event channels.
    pub channel_capacity: usize,
    /// Stage D smoke toggle: generate a probe egress packet when an announce ingress
    /// event is observed. Keep this off by default to avoid implicit behavior changes.
    pub emit_probe_on_ingress_announce: bool,
    /// Enable simple rebroadcast input for ingress decision policy.
    pub broadcast_enabled: bool,
    /// Keep up to this many packet hashes for simple duplicate filtering.
    pub duplicate_cache_size: usize,
    /// Keep up to this many destination->received_from path-state entries.
    pub path_state_cache_size: usize,
    /// Keep up to this many destination->known_hops observations.
    pub known_hops_cache_size: usize,
    /// Stage D path-request behavior flag mirroring std retransmit gate.
    pub retransmit_enabled: bool,
    /// Optional local destination address used for Stage E state parity.
    ///
    /// When set, embedded path-request/link-request decisions can use the same
    /// "is this destination local?" style input that std transport uses.
    pub local_address: Option<AddressHash>,
    /// Max rows for the intermediate [`crate::transport_engine::IntermediateLinkEntry`] table (FIFO eviction).
    pub intermediate_link_table_size: usize,
}

impl Default for EmbeddedTransportConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 16,
            emit_probe_on_ingress_announce: false,
            broadcast_enabled: false,
            duplicate_cache_size: 128,
            path_state_cache_size: 64,
            known_hops_cache_size: 64,
            retransmit_enabled: false,
            local_address: None,
            intermediate_link_table_size: 32,
        }
    }
}

/// Stage D embedded transport skeleton.
///
/// Current behavior:
/// - receives ingress packets from interfaces
/// - forwards all ingress events to subscribers
/// - maintains lightweight counters by packet type
/// - exposes egress channel sender/receiver for future wiring
pub struct EmbeddedTransport {
    ingress_tx: broadcast::Sender<RxMessage>,
    ingress_events_tx: broadcast::Sender<RxMessage>,
    egress_tx: broadcast::Sender<TxMessage>,
    command_tx: broadcast::Sender<EmbeddedCommand>,
    event_tx: broadcast::Sender<EmbeddedEvent>,
    interface_ingress_count: Arc<AtomicU32>,
    synthetic_ingress_count: Arc<AtomicU32>,
    announce_count: Arc<AtomicU32>,
    data_count: Arc<AtomicU32>,
    path_request_count: Arc<AtomicU32>,
    link_request_count: Arc<AtomicU32>,
    proof_count: Arc<AtomicU32>,
    link_pending_count: Arc<AtomicU32>,
    link_activated_count: Arc<AtomicU32>,
    data_deliver_local_count: Arc<AtomicU32>,
    data_forward_candidate_count: Arc<AtomicU32>,
    data_forward_queued_count: Arc<AtomicU32>,
    link_request_forward_queued_count: Arc<AtomicU32>,
    intermediate_link_insert_count: Arc<AtomicU32>,
    intermediate_link_duplicate_skip_count: Arc<AtomicU32>,
    link_proof_propagate_queued_count: Arc<AtomicU32>,
    link_keepalive_propagate_queued_count: Arc<AtomicU32>,
    egress_generated_count: Arc<AtomicU32>,
    egress_dropped_count: Arc<AtomicU32>,
    event_dropped_count: Arc<AtomicU32>,
    cancel: CancellationToken,
}

/// Snapshot of lightweight Stage D runner counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedTransportStats {
    pub interface_ingress_count: u32,
    pub synthetic_ingress_count: u32,
    pub announce_count: u32,
    pub data_count: u32,
    pub path_request_count: u32,
    pub link_request_count: u32,
    pub proof_count: u32,
    pub link_activated_count: u32,
    pub link_pending_count: u32,
    /// `Data` ingress classified as local delivery (shared `SingleDataRoute::DeliverLocal`).
    pub data_deliver_local_count: u32,
    /// `Data` ingress classified as forward candidate (shared `SingleDataRoute::Forward`).
    pub data_forward_candidate_count: u32,
    /// Non-path-request `Data` forwards actually queued (std `send_to_next_hop` path).
    pub data_forward_queued_count: u32,
    /// Intermediate `LinkRequest` forwards actually queued (std `handle_link_request_as_intermediate`).
    pub link_request_forward_queued_count: u32,
    pub intermediate_link_insert_count: u32,
    pub intermediate_link_duplicate_skip_count: u32,
    pub link_proof_propagate_queued_count: u32,
    pub link_keepalive_propagate_queued_count: u32,
    pub egress_generated_count: u32,
    pub egress_dropped_count: u32,
    pub event_dropped_count: u32,
}

/// Packet ingress/egress boundary used by embedded drivers and host simulators.
///
/// Hardware interfaces and virtual mesh simulations should depend on this small
/// surface instead of reaching into runner internals. The runner still owns
/// protocol classification, duplicate filtering, and egress decisions.
pub trait EmbeddedTransportPort {
    fn inject_from_interface(&self, message: RxMessage);
    fn egress_receiver(&self) -> broadcast::Receiver<TxMessage>;
    fn stats(&self) -> EmbeddedTransportStats;
}

impl EmbeddedTransport {
    pub fn new(config: EmbeddedTransportConfig) -> Self {
        let (ingress_tx, ingress_rx): (
            broadcast::Sender<RxMessage>,
            broadcast::Receiver<RxMessage>,
        ) = broadcast::channel(config.channel_capacity);
        let (ingress_events_tx, _): (broadcast::Sender<RxMessage>, broadcast::Receiver<RxMessage>) =
            broadcast::channel(config.channel_capacity);
        let (egress_tx, _): (broadcast::Sender<TxMessage>, broadcast::Receiver<TxMessage>) =
            broadcast::channel(config.channel_capacity);
        let (command_tx, command_rx): (
            broadcast::Sender<EmbeddedCommand>,
            broadcast::Receiver<EmbeddedCommand>,
        ) = broadcast::channel(config.channel_capacity);
        let (event_tx, _): (
            broadcast::Sender<EmbeddedEvent>,
            broadcast::Receiver<EmbeddedEvent>,
        ) = broadcast::channel(config.channel_capacity);
        let cancel = CancellationToken::new();
        let interface_ingress_count = Arc::new(AtomicU32::new(0));
        let synthetic_ingress_count = Arc::new(AtomicU32::new(0));
        let announce_count = Arc::new(AtomicU32::new(0));
        let data_count = Arc::new(AtomicU32::new(0));
        let path_request_count = Arc::new(AtomicU32::new(0));
        let link_request_count = Arc::new(AtomicU32::new(0));
        let proof_count = Arc::new(AtomicU32::new(0));
        let link_pending_count = Arc::new(AtomicU32::new(0));
        let link_activated_count = Arc::new(AtomicU32::new(0));
        let data_deliver_local_count = Arc::new(AtomicU32::new(0));
        let data_forward_candidate_count = Arc::new(AtomicU32::new(0));
        let data_forward_queued_count = Arc::new(AtomicU32::new(0));
        let link_request_forward_queued_count = Arc::new(AtomicU32::new(0));
        let intermediate_link_insert_count = Arc::new(AtomicU32::new(0));
        let intermediate_link_duplicate_skip_count = Arc::new(AtomicU32::new(0));
        let link_proof_propagate_queued_count = Arc::new(AtomicU32::new(0));
        let link_keepalive_propagate_queued_count = Arc::new(AtomicU32::new(0));
        let egress_generated_count = Arc::new(AtomicU32::new(0));
        let egress_dropped_count = Arc::new(AtomicU32::new(0));
        let event_dropped_count = Arc::new(AtomicU32::new(0));
        let auto_probe_on_ingress =
            Arc::new(AtomicBool::new(config.emit_probe_on_ingress_announce));

        // Stage D runner task: classifies ingress and publishes ingress events.
        {
            let mut ingress_rx: broadcast::Receiver<RxMessage> = ingress_rx;
            let ingress_events_tx = ingress_events_tx.clone();
            let cancel_clone = cancel.clone();
            let interface_ingress_count = interface_ingress_count.clone();
            let synthetic_ingress_count = synthetic_ingress_count.clone();
            let announce_count = announce_count.clone();
            let data_count = data_count.clone();
            let path_request_count = path_request_count.clone();
            let link_request_count = link_request_count.clone();
            let proof_count = proof_count.clone();
            let link_pending_count = link_pending_count.clone();
            let link_activated_count = link_activated_count.clone();
            let data_deliver_local_count = data_deliver_local_count.clone();
            let data_forward_candidate_count = data_forward_candidate_count.clone();
            let data_forward_queued_count = data_forward_queued_count.clone();
            let link_request_forward_queued_count = link_request_forward_queued_count.clone();
            let intermediate_link_insert_count = intermediate_link_insert_count.clone();
            let intermediate_link_duplicate_skip_count =
                intermediate_link_duplicate_skip_count.clone();
            let link_proof_propagate_queued_count = link_proof_propagate_queued_count.clone();
            let link_keepalive_propagate_queued_count =
                link_keepalive_propagate_queued_count.clone();
            let egress_generated_count = egress_generated_count.clone();
            let egress_dropped_count = egress_dropped_count.clone();
            let event_dropped_count = event_dropped_count.clone();
            let auto_probe_on_ingress = auto_probe_on_ingress.clone();
            let egress_tx = egress_tx.clone();
            let event_tx = event_tx.clone();
            let fixed_dest_path_requests = path_request_fixed_destination();
            let broadcast_enabled = config.broadcast_enabled;
            let duplicate_cache_size = config.duplicate_cache_size.max(1);
            let path_state_cache_size = config.path_state_cache_size.max(1);
            let known_hops_cache_size = config.known_hops_cache_size.max(1);
            let retransmit_enabled = config.retransmit_enabled;
            let local_address = config.local_address;
            let intermediate_link_table_size = config.intermediate_link_table_size.max(1);
            spawn(async move {
                // Tiny lifecycle state used only for Stage D observability:
                // LinkRequest -> pending destination, Proof -> activated destination.
                let mut pending_links: Vec<AddressHash> = Vec::new();
                let mut intermediate_links: Vec<IntermediateLinkEntry> = Vec::new();
                let mut seen_packets: Vec<crate::hash::Hash> = Vec::new();
                let mut path_received_from: Vec<(AddressHash, AddressHash)> = Vec::new();
                let mut path_known_hops: Vec<(AddressHash, u8)> = Vec::new();
                loop {
                    if cancel_clone.is_cancelled() {
                        break;
                    }
                    if let Ok(msg) = ingress_rx.recv().await {
                        let source_address = msg.address;
                        let destination = msg.packet.destination;
                        if source_address != AddressHash::new_empty() {
                            if let Some(pos) = path_received_from
                                .iter()
                                .position(|(dest, _)| *dest == destination)
                            {
                                path_received_from[pos] = (destination, source_address);
                            } else {
                                path_received_from.push((destination, source_address));
                                if path_received_from.len() > path_state_cache_size {
                                    let _ = path_received_from.remove(0);
                                }
                            }
                            // Stage D approximation: record latest observed ingress hops for destination.
                            if let Some(pos) = path_known_hops
                                .iter()
                                .position(|(dest, _)| *dest == destination)
                            {
                                path_known_hops[pos] = (destination, msg.packet.header.hops);
                            } else {
                                path_known_hops.push((destination, msg.packet.header.hops));
                                if path_known_hops.len() > known_hops_cache_size {
                                    let _ = path_known_hops.remove(0);
                                }
                            }
                        }
                        let source = if msg.address == AddressHash::new_empty() {
                            synthetic_ingress_count.fetch_add(1, Ordering::Relaxed);
                            EmbeddedIngressSource::Synthetic
                        } else {
                            interface_ingress_count.fetch_add(1, Ordering::Relaxed);
                            EmbeddedIngressSource::Interface
                        };
                        if event_tx
                            .send(EmbeddedEvent::IngressClassified {
                                source,
                                packet_type: msg.packet.header.packet_type,
                                destination: msg.packet.destination,
                            })
                            .is_err()
                        {
                            event_dropped_count.fetch_add(1, Ordering::Relaxed);
                        }
                        let fixed_destination_handled =
                            should_handle_fixed_destination_path_request(
                                &msg.packet.destination,
                                &fixed_dest_path_requests,
                                msg.packet.header.packet_type,
                                msg.packet.context,
                                msg.packet.data.as_slice(),
                            );
                        let packet_hash = msg.packet.hash();
                        let is_new = !seen_packets.contains(&packet_hash);
                        if is_new {
                            seen_packets.push(packet_hash);
                            if seen_packets.len() > duplicate_cache_size {
                                let _ = seen_packets.remove(0);
                            }
                        }
                        let destination_pending = if should_consider_in_link_pending_proof(
                            msg.packet.header.packet_type,
                            msg.packet.context,
                        ) {
                            pending_links.contains(&msg.packet.destination)
                        } else {
                            false
                        };
                        let in_link_pending_proof = is_in_link_pending_proof(
                            msg.packet.header.packet_type,
                            msg.packet.context,
                            destination_pending,
                        );
                        let duplicate = decide_duplicate_outcome(
                            msg.packet.header.packet_type,
                            msg.packet.context,
                            in_link_pending_proof,
                            is_new,
                        );
                        let ingress = decide_ingress_from_input(IngressDecisionInput {
                            packet_type: msg.packet.header.packet_type,
                            fixed_destination_handled,
                            duplicate,
                            broadcast_enabled,
                        });
                        let emit_recursive_path_request =
                            |exclude_iface: AddressHash,
                             destination: AddressHash,
                             emit_announce_event: bool| {
                                let mut packet = Packet::default();
                                packet.header.packet_type = PacketType::Data;
                                packet.destination = destination;
                                packet.context = crate::packet::PacketContext::Request;
                                packet.data = PacketDataBuffer::new_from_slice(
                                    STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD,
                                );
                                if egress_tx
                                    .send(TxMessage {
                                        tx_type: TxMessageType::Broadcast(Some(exclude_iface)),
                                        packet,
                                    })
                                    .is_err()
                                {
                                    egress_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                                egress_generated_count.fetch_add(1, Ordering::Relaxed);
                                if event_tx
                                    .send(EmbeddedEvent::EgressGenerated {
                                        destination,
                                        bytes: STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD.len(),
                                    })
                                    .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                                if emit_announce_event
                                    && event_tx
                                        .send(EmbeddedEvent::AnnounceTriggeredPathRequest {
                                            destination,
                                            bytes: STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD.len(),
                                        })
                                        .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                            };
                        let build_path_request_input = || {
                            let state = lookup_path_request_state(
                                msg.packet.destination,
                                path_received_from.as_slice(),
                                path_known_hops.as_slice(),
                            );
                            let has_local_destination = local_address
                                .map(|addr| addr == msg.packet.destination)
                                .unwrap_or(false);
                            build_path_request_decision_input(
                                msg.packet.destination,
                                msg.address,
                                msg.packet.transport,
                                has_local_destination,
                                retransmit_enabled,
                                state,
                            )
                        };
                        let handle_path_request_action =
                            |action: PathRequestAction,
                             destination: AddressHash,
                             announce_triggered: bool| {
                                match decide_staged_path_request_egress(action, announce_triggered)
                                {
                                    StagedPathRequestEgressDecision::EmitRecursive {
                                        exclude_iface,
                                    } => {
                                        emit_recursive_path_request(
                                            exclude_iface,
                                            destination,
                                            announce_triggered,
                                        );
                                    }
                                    StagedPathRequestEgressDecision::CountOnly => {
                                        // Mirror std policy branch: no recursive egress emission here.
                                        path_request_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                    StagedPathRequestEgressDecision::None => {}
                                }
                            };
                        let execute_path_request_for_current_packet = |announce_triggered: bool| {
                            let input = build_path_request_input();
                            let action = decide_path_request_action_from_input(input);
                            handle_path_request_action(
                                action,
                                msg.packet.destination,
                                announce_triggered,
                            );
                        };
                        let execute_link_lifecycle_transition =
                            |pending_links: &mut Vec<AddressHash>,
                             destination: AddressHash,
                             transition: LinkLifecycleTransition| {
                                match transition {
                                    LinkLifecycleTransition::AddPending => {
                                        pending_links.push(destination);
                                        link_pending_count
                                            .store(pending_links.len() as u32, Ordering::Relaxed);
                                        if event_tx
                                            .send(EmbeddedEvent::LinkLifecyclePending {
                                                destination,
                                            })
                                            .is_err()
                                        {
                                            event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    LinkLifecycleTransition::Activate => {
                                        if let Some(pos) =
                                            pending_links.iter().position(|d| *d == destination)
                                        {
                                            pending_links.swap_remove(pos);
                                            link_pending_count.store(
                                                pending_links.len() as u32,
                                                Ordering::Relaxed,
                                            );
                                        }
                                        link_activated_count.fetch_add(1, Ordering::Relaxed);
                                        if event_tx
                                            .send(EmbeddedEvent::LinkLifecycleActivated {
                                                destination,
                                            })
                                            .is_err()
                                        {
                                            event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    LinkLifecycleTransition::None => {}
                                }
                            };
                        match ingress {
                            IngressDecision::Dispatch {
                                action: IngressAction::Announce,
                                ..
                            } => {
                                announce_count.fetch_add(1, Ordering::Relaxed);
                                if auto_probe_on_ingress.load(Ordering::Relaxed) {
                                    execute_path_request_for_current_packet(true);
                                }
                            }
                            IngressDecision::Dispatch {
                                action: IngressAction::Data,
                                ..
                            } => {
                                data_count.fetch_add(1, Ordering::Relaxed);
                                if is_path_request_packet(
                                    msg.packet.header.packet_type,
                                    msg.packet.context,
                                    msg.packet.data.as_slice(),
                                ) {
                                    path_request_count.fetch_add(1, Ordering::Relaxed);
                                    execute_path_request_for_current_packet(false);
                                } else if msg.packet.header.destination_type
                                    == DestinationType::Single
                                {
                                    // Mirrors std `handle_data` for [`DestinationType::Single`] (not Link/Plain/Group).
                                    let has_local_destination = local_address
                                        .map(|addr| addr == msg.packet.destination)
                                        .unwrap_or(false);
                                    let maybe_next_hop = path_cache_lookup_next_hop(
                                        &path_received_from,
                                        msg.packet.destination,
                                    );
                                    let route = decide_single_data_route(has_local_destination);
                                    let mut forward_queued = false;
                                    match route {
                                        SingleDataRoute::DeliverLocal => {
                                            data_deliver_local_count
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        SingleDataRoute::Forward => {
                                            data_forward_candidate_count
                                                .fetch_add(1, Ordering::Relaxed);
                                            if let Some(nh) = maybe_next_hop {
                                                forward_queued = queue_path_table_forward(
                                                    &egress_tx,
                                                    &egress_generated_count,
                                                    &egress_dropped_count,
                                                    &msg.packet,
                                                    nh,
                                                    source_address,
                                                );
                                                if forward_queued {
                                                    data_forward_queued_count
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                        }
                                    }
                                    if event_tx
                                        .send(EmbeddedEvent::DataRouted {
                                            route,
                                            destination: msg.packet.destination,
                                            source: source_address,
                                            forward_queued,
                                        })
                                        .is_err()
                                    {
                                        event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                } else if msg.packet.header.destination_type
                                    == DestinationType::Link
                                {
                                    // Std `handle_keepalive_response` + `link_table.handle_keepalive` path.
                                    let first_byte = msg.packet.data.as_slice().first().copied();
                                    if should_handle_keepalive_response(
                                        msg.packet.context,
                                        first_byte,
                                    ) {
                                        let maybe_ka = intermediate_link_table_handle_keepalive(
                                            intermediate_links.as_slice(),
                                            &msg.packet,
                                        );
                                        match decide_proof_handle_followup(maybe_ka) {
                                            ProofHandleFollowup::SendDirect { packet, iface } => {
                                                if queue_prepared_direct(
                                                    &egress_tx,
                                                    &egress_generated_count,
                                                    &egress_dropped_count,
                                                    packet,
                                                    iface,
                                                ) {
                                                    link_keepalive_propagate_queued_count
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            ProofHandleFollowup::NoOp => {}
                                        }
                                    }
                                }
                            }
                            IngressDecision::Dispatch {
                                action: IngressAction::LinkRequest,
                                ..
                            } => {
                                link_request_count.fetch_add(1, Ordering::Relaxed);
                                let has_local_destination = local_address
                                    .map(|addr| addr == msg.packet.destination)
                                    .unwrap_or(false);
                                let maybe_next_hop = path_cache_lookup_next_hop(
                                    &path_received_from,
                                    msg.packet.destination,
                                );
                                let has_next_hop = maybe_next_hop.is_some();
                                match decide_link_request_route(has_local_destination, has_next_hop)
                                {
                                    LinkRequestRoute::LocalDestination => {
                                        let in_link_already_exists =
                                            pending_links.contains(&msg.packet.destination);
                                        let proof_requested =
                                            link_request_destination_requests_proof(
                                                msg.packet.header.packet_type,
                                                has_local_destination,
                                            );
                                        match decide_link_lifecycle_transition(
                                            IngressAction::LinkRequest,
                                            proof_requested,
                                            in_link_already_exists,
                                            in_link_already_exists,
                                        ) {
                                            transition @ (LinkLifecycleTransition::AddPending
                                            | LinkLifecycleTransition::None) => {
                                                execute_link_lifecycle_transition(
                                                    &mut pending_links,
                                                    msg.packet.destination,
                                                    transition,
                                                );
                                            }
                                            LinkLifecycleTransition::Activate => {}
                                        }
                                    }
                                    LinkRequestRoute::Intermediate => {
                                        let mut forward_queued = false;
                                        let mut link_table_inserted = false;
                                        if decide_intermediate_link_request_action(has_next_hop)
                                            == IntermediateLinkRequestAction::AddLinkTableAndForward
                                        {
                                            if let Some(nh) = maybe_next_hop {
                                                link_table_inserted =
                                                    try_register_intermediate_link_entry(
                                                        &mut intermediate_links,
                                                        intermediate_link_table_size,
                                                        &msg.packet,
                                                        msg.packet.destination,
                                                        source_address,
                                                        nh,
                                                        source_address,
                                                    );
                                                if link_table_inserted {
                                                    intermediate_link_insert_count
                                                        .fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    intermediate_link_duplicate_skip_count
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                                forward_queued = queue_path_table_forward(
                                                    &egress_tx,
                                                    &egress_generated_count,
                                                    &egress_dropped_count,
                                                    &msg.packet,
                                                    nh,
                                                    source_address,
                                                );
                                                if forward_queued {
                                                    link_request_forward_queued_count
                                                        .fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                        }
                                        if event_tx
                                            .send(EmbeddedEvent::LinkRequestRouted {
                                                route: LinkRequestRoute::Intermediate,
                                                destination: msg.packet.destination,
                                                source: source_address,
                                                forward_queued,
                                                link_table_inserted,
                                            })
                                            .is_err()
                                        {
                                            event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    LinkRequestRoute::DropUnknown => {
                                        if event_tx
                                            .send(EmbeddedEvent::LinkRequestRouted {
                                                route: LinkRequestRoute::DropUnknown,
                                                destination: msg.packet.destination,
                                                source: source_address,
                                                forward_queued: false,
                                                link_table_inserted: false,
                                            })
                                            .is_err()
                                        {
                                            event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            IngressDecision::Dispatch {
                                action: IngressAction::Proof,
                                ..
                            } => {
                                proof_count.fetch_add(1, Ordering::Relaxed);
                                let pending_link_exists =
                                    pending_links.contains(&msg.packet.destination);
                                match decide_link_lifecycle_transition(
                                    IngressAction::Proof,
                                    false,
                                    false,
                                    pending_link_exists,
                                ) {
                                    transition @ (LinkLifecycleTransition::Activate
                                    | LinkLifecycleTransition::None) => {
                                        execute_link_lifecycle_transition(
                                            &mut pending_links,
                                            msg.packet.destination,
                                            transition,
                                        );
                                    }
                                    LinkLifecycleTransition::AddPending => {}
                                }
                                let maybe_prop = intermediate_link_table_apply_proof(
                                    intermediate_links.as_mut_slice(),
                                    &msg.packet,
                                );
                                match decide_proof_handle_followup(maybe_prop) {
                                    ProofHandleFollowup::SendDirect { packet, iface } => {
                                        if queue_prepared_direct(
                                            &egress_tx,
                                            &egress_generated_count,
                                            &egress_dropped_count,
                                            packet,
                                            iface,
                                        ) {
                                            link_proof_propagate_queued_count
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    ProofHandleFollowup::NoOp => {}
                                }
                            }
                            IngressDecision::HandleFixedDestination(_) => {
                                // Mirror std behavior: fixed path-request handling consumes
                                // packet before normal dispatch.
                                path_request_count.fetch_add(1, Ordering::Relaxed);
                                execute_path_request_for_current_packet(false);
                            }
                            IngressDecision::DropDuplicate(_) => {}
                        }
                        let _ = ingress_events_tx.send(msg);
                    }
                }
            });
        }

        // Stage D typed command loop.
        {
            let mut command_rx: broadcast::Receiver<EmbeddedCommand> = command_rx;
            let cancel_clone = cancel.clone();
            let egress_tx = egress_tx.clone();
            let egress_generated_count = egress_generated_count.clone();
            let egress_dropped_count = egress_dropped_count.clone();
            let event_dropped_count = event_dropped_count.clone();
            let event_tx = event_tx.clone();
            let auto_probe_on_ingress = auto_probe_on_ingress.clone();
            spawn(async move {
                loop {
                    if cancel_clone.is_cancelled() {
                        break;
                    }
                    if let Ok(cmd) = command_rx.recv().await {
                        match cmd {
                            EmbeddedCommand::EmitProbe { destination } => {
                                let mut packet = Packet::default();
                                packet.header.packet_type = PacketType::Data;
                                packet.destination = destination;
                                packet.context = crate::packet::PacketContext::Request;
                                packet.data = PacketDataBuffer::new_from_slice(
                                    STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD,
                                );
                                if egress_tx
                                    .send(TxMessage {
                                        tx_type: TxMessageType::Broadcast(None),
                                        packet,
                                    })
                                    .is_err()
                                {
                                    egress_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                                egress_generated_count.fetch_add(1, Ordering::Relaxed);
                                if event_tx
                                    .send(EmbeddedEvent::EgressGenerated {
                                        destination,
                                        bytes: STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD.len(),
                                    })
                                    .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            EmbeddedCommand::SetAutoProbeOnIngressAnnounce(enabled) => {
                                auto_probe_on_ingress.store(enabled, Ordering::Relaxed);
                                if event_tx
                                    .send(EmbeddedEvent::AutoProbeOnIngressChanged(enabled))
                                    .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            EmbeddedCommand::EmitSynthetic {
                                packet_type,
                                destination,
                                payload,
                            } => {
                                let mut packet = Packet::default();
                                packet.header.packet_type = packet_type;
                                packet.destination = destination;
                                packet.data = PacketDataBuffer::new_from_slice(payload);
                                if egress_tx
                                    .send(TxMessage {
                                        tx_type: TxMessageType::Broadcast(None),
                                        packet,
                                    })
                                    .is_err()
                                {
                                    egress_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                                egress_generated_count.fetch_add(1, Ordering::Relaxed);
                                if event_tx
                                    .send(EmbeddedEvent::SyntheticEgressRequested {
                                        packet_type,
                                        destination,
                                        bytes: payload.len(),
                                    })
                                    .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            EmbeddedCommand::EmitSyntheticBytes {
                                packet_type,
                                destination,
                                payload,
                            } => {
                                let mut packet = Packet::default();
                                packet.header.packet_type = packet_type;
                                packet.destination = destination;
                                packet.data = payload;
                                if egress_tx
                                    .send(TxMessage {
                                        tx_type: TxMessageType::Broadcast(None),
                                        packet,
                                    })
                                    .is_err()
                                {
                                    egress_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                                egress_generated_count.fetch_add(1, Ordering::Relaxed);
                                if event_tx
                                    .send(EmbeddedEvent::SyntheticEgressRequested {
                                        packet_type,
                                        destination,
                                        bytes: payload.len(),
                                    })
                                    .is_err()
                                {
                                    event_dropped_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            });
        }

        Self {
            ingress_tx,
            ingress_events_tx,
            egress_tx,
            command_tx,
            event_tx,
            interface_ingress_count,
            synthetic_ingress_count,
            announce_count,
            data_count,
            path_request_count,
            link_request_count,
            proof_count,
            link_pending_count,
            link_activated_count,
            data_deliver_local_count,
            data_forward_candidate_count,
            data_forward_queued_count,
            link_request_forward_queued_count,
            intermediate_link_insert_count,
            intermediate_link_duplicate_skip_count,
            link_proof_propagate_queued_count,
            link_keepalive_propagate_queued_count,
            egress_generated_count,
            egress_dropped_count,
            event_dropped_count,
            cancel,
        }
    }

    /// Inject packet received from interface side.
    pub fn ingress_sender(&self) -> broadcast::Sender<RxMessage> {
        self.ingress_tx.clone()
    }

    /// Inject one fully-formed interface-origin message.
    pub fn inject_from_interface(&self, message: RxMessage) {
        let _ = self.ingress_tx.send(message);
    }

    /// Convenience helper for Stage D smoke: inject a synthetic announce ingress event.
    ///
    /// This lets embedded callers exercise the runner without constructing full RxMessage
    /// packets at each call site.
    pub fn inject_announce(&self, destination: AddressHash) {
        let mut packet = Packet::default();
        packet.header.packet_type = PacketType::Announce;
        packet.destination = destination;
        let _ = self.ingress_tx.send(RxMessage {
            address: AddressHash::new_empty(),
            packet,
        });
    }

    /// Inject one announce ingress packet marked as coming from a real interface.
    ///
    /// Beginner note: use this for packets decoded from radio/UART so we can
    /// separate real traffic from synthetic test injections in stats/events.
    pub fn inject_announce_from_interface(
        &self,
        source_address: AddressHash,
        destination: AddressHash,
    ) {
        let mut packet = Packet::default();
        packet.header.packet_type = PacketType::Announce;
        packet.destination = destination;
        let _ = self.ingress_tx.send(RxMessage {
            address: source_address,
            packet,
        });
    }

    /// Convenience helper for Stage D smoke: inject one ingress packet with explicit type/payload.
    ///
    /// Beginner note: this pretends "the radio just delivered this packet to us".
    /// It is a safe way to exercise embedded runner logic even when real RF timing is noisy.
    pub fn inject_ingress_packet(
        &self,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &'static [u8],
    ) {
        let mut packet = Packet::default();
        packet.header.packet_type = packet_type;
        packet.destination = destination;
        packet.data = PacketDataBuffer::new_from_slice(payload);
        // Keep Data as Request context when payload is the staged path marker.
        if packet_type == PacketType::Data && payload == STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD {
            packet.context = crate::packet::PacketContext::Request;
        }
        let _ = self.ingress_tx.send(RxMessage {
            address: AddressHash::new_empty(),
            packet,
        });
    }

    /// Inject one synthetic ingress packet with runtime payload bytes.
    ///
    /// This is Stage E-friendly: callers can forward real interface payloads
    /// without requiring a `'static` payload reference.
    pub fn inject_ingress_packet_bytes(
        &self,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &[u8],
    ) {
        let mut packet = Packet::default();
        packet.header.packet_type = packet_type;
        packet.destination = destination;
        packet.data = PacketDataBuffer::new_from_slice(payload);
        if packet_type == PacketType::Data && payload == STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD {
            packet.context = crate::packet::PacketContext::Request;
        }
        let _ = self.ingress_tx.send(RxMessage {
            address: AddressHash::new_empty(),
            packet,
        });
    }

    /// Inject one ingress packet marked as coming from a real interface.
    pub fn inject_ingress_packet_from_interface(
        &self,
        source_address: AddressHash,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &'static [u8],
    ) {
        let mut packet = Packet::default();
        packet.header.packet_type = packet_type;
        packet.destination = destination;
        packet.data = PacketDataBuffer::new_from_slice(payload);
        if packet_type == PacketType::Data && payload == STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD {
            packet.context = crate::packet::PacketContext::Request;
        }
        let _ = self.ingress_tx.send(RxMessage {
            address: source_address,
            packet,
        });
    }

    /// Inject one interface-origin ingress packet with runtime payload bytes.
    ///
    /// This is used by Stage E board flow so received radio payloads can be
    /// fed into embedded transport classification/state counters directly.
    pub fn inject_ingress_packet_from_interface_bytes(
        &self,
        source_address: AddressHash,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &[u8],
    ) {
        let mut packet = Packet::default();
        packet.header.packet_type = packet_type;
        packet.destination = destination;
        packet.data = PacketDataBuffer::new_from_slice(payload);
        if packet_type == PacketType::Data && payload == STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD {
            packet.context = crate::packet::PacketContext::Request;
        }
        let _ = self.ingress_tx.send(RxMessage {
            address: source_address,
            packet,
        });
    }

    /// Subscribe to ingress events observed by the embedded runner.
    pub fn ingress_events(&self) -> broadcast::Receiver<RxMessage> {
        self.ingress_events_tx.subscribe()
    }

    /// Send a typed command to the embedded runner.
    pub fn command_sender(&self) -> broadcast::Sender<EmbeddedCommand> {
        self.command_tx.clone()
    }

    /// Convenience helper: emit one probe packet toward `destination`.
    pub fn request_probe(&self, destination: AddressHash) {
        let _ = self
            .command_tx
            .send(EmbeddedCommand::EmitProbe { destination });
    }

    /// Convenience helper: enable/disable automatic probe generation on ingress announces.
    pub fn set_auto_probe_on_ingress_announce(&self, enabled: bool) {
        let _ = self
            .command_tx
            .send(EmbeddedCommand::SetAutoProbeOnIngressAnnounce(enabled));
    }

    /// Convenience helper: emit a synthetic packet type for staged embedded-runner validation.
    pub fn request_synthetic(
        &self,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &'static [u8],
    ) {
        let _ = self.command_tx.send(EmbeddedCommand::EmitSynthetic {
            packet_type,
            destination,
            payload,
        });
    }

    /// Convenience helper: emit a synthetic packet with runtime payload bytes.
    pub fn request_synthetic_bytes(
        &self,
        packet_type: PacketType,
        destination: AddressHash,
        payload: &[u8],
    ) {
        let _ = self.command_tx.send(EmbeddedCommand::EmitSyntheticBytes {
            packet_type,
            destination,
            payload: PacketDataBuffer::new_from_slice(payload),
        });
    }

    /// Subscribe to typed embedded-runner events.
    pub fn events(&self) -> broadcast::Receiver<EmbeddedEvent> {
        self.event_tx.subscribe()
    }

    /// Sender side of egress queue (to be wired to iface TX workers in next Stage D steps).
    pub fn egress_sender(&self) -> broadcast::Sender<TxMessage> {
        self.egress_tx.clone()
    }

    /// Subscribe to egress queue.
    pub fn egress_receiver(&self) -> broadcast::Receiver<TxMessage> {
        self.egress_tx.subscribe()
    }

    /// Number of announce packets seen by the embedded runner.
    pub fn announce_count(&self) -> u32 {
        self.announce_count.load(Ordering::Relaxed)
    }

    /// Number of ingress packets observed from real interface paths.
    pub fn interface_ingress_count(&self) -> u32 {
        self.interface_ingress_count.load(Ordering::Relaxed)
    }

    /// Number of ingress packets observed from synthetic Stage D injections.
    pub fn synthetic_ingress_count(&self) -> u32 {
        self.synthetic_ingress_count.load(Ordering::Relaxed)
    }

    /// Number of data packets seen by the embedded runner.
    pub fn data_count(&self) -> u32 {
        self.data_count.load(Ordering::Relaxed)
    }

    /// Number of path-request-like packets seen by the embedded runner.
    pub fn path_request_count(&self) -> u32 {
        self.path_request_count.load(Ordering::Relaxed)
    }

    /// Number of link request packets seen by the embedded runner.
    pub fn link_request_count(&self) -> u32 {
        self.link_request_count.load(Ordering::Relaxed)
    }

    /// Number of proof packets seen by the embedded runner.
    pub fn proof_count(&self) -> u32 {
        self.proof_count.load(Ordering::Relaxed)
    }

    /// Number of link lifecycles that reached the activated transition in Stage D.
    pub fn link_activated_count(&self) -> u32 {
        self.link_activated_count.load(Ordering::Relaxed)
    }

    /// Number of pending link lifecycles (seen LinkRequest without matching Proof yet).
    pub fn link_pending_count(&self) -> u32 {
        self.link_pending_count.load(Ordering::Relaxed)
    }

    /// `Data` packets classified as local delivery (non-path-request path).
    pub fn data_deliver_local_count(&self) -> u32 {
        self.data_deliver_local_count.load(Ordering::Relaxed)
    }

    /// `Data` packets classified as forward candidates (non-path-request path).
    pub fn data_forward_candidate_count(&self) -> u32 {
        self.data_forward_candidate_count.load(Ordering::Relaxed)
    }

    /// `Data` packets for which a Type2 forward was queued (std `send_to_next_hop`).
    pub fn data_forward_queued_count(&self) -> u32 {
        self.data_forward_queued_count.load(Ordering::Relaxed)
    }

    /// Intermediate `LinkRequest` packets for which a Type2 forward was queued.
    pub fn link_request_forward_queued_count(&self) -> u32 {
        self.link_request_forward_queued_count
            .load(Ordering::Relaxed)
    }

    pub fn intermediate_link_insert_count(&self) -> u32 {
        self.intermediate_link_insert_count.load(Ordering::Relaxed)
    }

    pub fn intermediate_link_duplicate_skip_count(&self) -> u32 {
        self.intermediate_link_duplicate_skip_count
            .load(Ordering::Relaxed)
    }

    pub fn link_proof_propagate_queued_count(&self) -> u32 {
        self.link_proof_propagate_queued_count
            .load(Ordering::Relaxed)
    }

    pub fn link_keepalive_propagate_queued_count(&self) -> u32 {
        self.link_keepalive_propagate_queued_count
            .load(Ordering::Relaxed)
    }

    /// Return `(announce_count, data_count)` in one call.
    pub fn counters(&self) -> (u32, u32) {
        (self.announce_count(), self.data_count())
    }

    /// Number of egress messages generated by the Stage D runner.
    pub fn egress_generated_count(&self) -> u32 {
        self.egress_generated_count.load(Ordering::Relaxed)
    }

    /// Number of egress messages dropped because egress channel was full.
    pub fn egress_dropped_count(&self) -> u32 {
        self.egress_dropped_count.load(Ordering::Relaxed)
    }

    /// Number of typed events dropped because event channel was full.
    pub fn event_dropped_count(&self) -> u32 {
        self.event_dropped_count.load(Ordering::Relaxed)
    }

    /// Return all Stage D runner counters in one call.
    pub fn stats(&self) -> EmbeddedTransportStats {
        EmbeddedTransportStats {
            interface_ingress_count: self.interface_ingress_count(),
            synthetic_ingress_count: self.synthetic_ingress_count(),
            announce_count: self.announce_count(),
            data_count: self.data_count(),
            path_request_count: self.path_request_count(),
            link_request_count: self.link_request_count(),
            proof_count: self.proof_count(),
            link_activated_count: self.link_activated_count(),
            link_pending_count: self.link_pending_count(),
            data_deliver_local_count: self.data_deliver_local_count(),
            data_forward_candidate_count: self.data_forward_candidate_count(),
            data_forward_queued_count: self.data_forward_queued_count(),
            link_request_forward_queued_count: self.link_request_forward_queued_count(),
            intermediate_link_insert_count: self.intermediate_link_insert_count(),
            intermediate_link_duplicate_skip_count: self.intermediate_link_duplicate_skip_count(),
            link_proof_propagate_queued_count: self.link_proof_propagate_queued_count(),
            link_keepalive_propagate_queued_count: self.link_keepalive_propagate_queued_count(),
            egress_generated_count: self.egress_generated_count(),
            egress_dropped_count: self.egress_dropped_count(),
            event_dropped_count: self.event_dropped_count(),
        }
    }
}

impl EmbeddedTransportPort for EmbeddedTransport {
    fn inject_from_interface(&self, message: RxMessage) {
        EmbeddedTransport::inject_from_interface(self, message);
    }

    fn egress_receiver(&self) -> broadcast::Receiver<TxMessage> {
        EmbeddedTransport::egress_receiver(self)
    }

    fn stats(&self) -> EmbeddedTransportStats {
        EmbeddedTransport::stats(self)
    }
}

impl Drop for EmbeddedTransport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
