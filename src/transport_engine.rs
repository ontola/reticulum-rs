//! Shared, runtime-agnostic ingress decision logic.
//!
//! This module is intentionally small and no-std friendly so both std transport
//! and embedded Stage D seam can share ingress policy without pulling std-only
//! link modules into embedded builds.

extern crate alloc;

use alloc::vec::Vec;

#[cfg(feature = "std")]
use crate::destination::link::LinkHandleResult;
use crate::destination::{DestinationName, PlainInputDestination};
use crate::hash::{AddressHash, Hash};
use crate::identity::{EmptyIdentity, PUBLIC_KEY_LENGTH};
use crate::packet::{Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType};
use core::time::Duration;
use sha2::Digest;

/// Runtime-agnostic action chosen for packet ingress dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressAction {
    Announce,
    LinkRequest,
    Proof,
    Data,
}

/// Runtime-agnostic decision for how to process a received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDecision {
    /// Packet was already handled by fixed-destination logic.
    HandleFixedDestination(IngressReason),
    /// Packet should be dropped as duplicate.
    DropDuplicate(IngressReason),
    /// Packet should be dispatched to protocol handlers.
    Dispatch {
        /// Whether packet should be rebroadcast before dispatch.
        rebroadcast: bool,
        /// Protocol action to execute.
        action: IngressAction,
        /// Why this dispatch path was selected.
        reason: IngressReason,
    },
}

/// Shared normalized ingress decision inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressDecisionInput {
    pub packet_type: PacketType,
    pub fixed_destination_handled: bool,
    pub duplicate: DuplicateOutcome,
    pub broadcast_enabled: bool,
}

/// Explanation for ingress decision paths, used for traceability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressReason {
    FixedDestinationMatched,
    DuplicateFiltered,
    FreshPacketDispatched,
}

/// Determine ingress handling without runtime-specific dependencies.
pub fn decide_ingress(
    packet_type: PacketType,
    fixed_destination_handled: bool,
    is_duplicate: bool,
    broadcast_enabled: bool,
) -> IngressDecision {
    if fixed_destination_handled {
        return IngressDecision::HandleFixedDestination(IngressReason::FixedDestinationMatched);
    }

    if is_duplicate {
        return IngressDecision::DropDuplicate(IngressReason::DuplicateFiltered);
    }

    let rebroadcast = broadcast_enabled && packet_type != PacketType::Announce;
    let action = match packet_type {
        PacketType::Announce => IngressAction::Announce,
        PacketType::LinkRequest => IngressAction::LinkRequest,
        PacketType::Proof => IngressAction::Proof,
        PacketType::Data => IngressAction::Data,
    };

    IngressDecision::Dispatch {
        rebroadcast,
        action,
        reason: IngressReason::FreshPacketDispatched,
    }
}

/// Runtime-agnostic route decision for link request packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRequestRoute {
    LocalDestination,
    Intermediate,
    DropUnknown,
}

/// Determine how a link request should be routed.
pub fn decide_link_request_route(
    has_local_destination: bool,
    has_next_hop: bool,
) -> LinkRequestRoute {
    if has_local_destination {
        LinkRequestRoute::LocalDestination
    } else if has_next_hop {
        LinkRequestRoute::Intermediate
    } else {
        LinkRequestRoute::DropUnknown
    }
}

/// Whether a link request expects a proof response at a **matching local destination**.
///
/// Mirrors [`crate::destination::SingleInputDestination::handle_packet`] for
/// [`PacketType::LinkRequest`] when the packet destination equals the local destination
/// (see `TODO: prove strategy` there). Used by the embedded runner when no destination
/// object is available.
pub fn link_request_destination_requests_proof(
    packet_type: PacketType,
    destination_matches_local: bool,
) -> bool {
    destination_matches_local && matches!(packet_type, PacketType::LinkRequest)
}

/// Runtime-agnostic action for destination-side link-request handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InLinkRegistrationAction {
    CreateAndStore,
    Skip,
}

/// Decide whether we should create/store a new in-link from a link request.
pub fn decide_in_link_registration_action(
    destination_requested_link_proof: bool,
    in_link_already_exists: bool,
) -> InLinkRegistrationAction {
    if destination_requested_link_proof && !in_link_already_exists {
        InLinkRegistrationAction::CreateAndStore
    } else {
        InLinkRegistrationAction::Skip
    }
}

/// Runtime-agnostic action for intermediate link-request forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntermediateLinkRequestAction {
    AddLinkTableAndForward,
    Skip,
}

/// Decide if intermediate link-request execution should run.
pub fn decide_intermediate_link_request_action(
    has_next_hop: bool,
) -> IntermediateLinkRequestAction {
    if has_next_hop {
        IntermediateLinkRequestAction::AddLinkTableAndForward
    } else {
        IntermediateLinkRequestAction::Skip
    }
}

/// Runtime-agnostic route decision for single-destination data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleDataRoute {
    DeliverLocal,
    Forward,
}

/// Decide whether a single-destination packet is local delivery or forwarding.
pub fn decide_single_data_route(has_local_destination: bool) -> SingleDataRoute {
    if has_local_destination {
        SingleDataRoute::DeliverLocal
    } else {
        SingleDataRoute::Forward
    }
}

/// Look up next hop for `destination` in a slim embedded path cache.
///
/// Each row is `(destination, received_from)` — the same pair [`crate::transport::path_table::PathEntry`]
/// stores after [`crate::transport::path_table::PathTable::handle_announce`]. Matches
/// [`crate::transport::path_table::PathTable::next_hop`].
pub fn path_cache_lookup_next_hop(
    path_received_from: &[(AddressHash, AddressHash)],
    destination: AddressHash,
) -> Option<AddressHash> {
    path_received_from
        .iter()
        .find(|(d, _)| *d == destination)
        .map(|(_, hop)| *hop)
}

/// Build a Type2 outbound packet with `transport` set to `next_hop`, matching
/// [`crate::transport::path_table::PathTable::handle_inbound_packet`] (forward path).
pub fn build_packet_forward_type2(original: &Packet, next_hop: AddressHash) -> Packet {
    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            hops: original.header.hops.saturating_add(1),
            ..original.header
        },
        ifac: None,
        destination: original.destination,
        transport: Some(next_hop),
        context: original.context,
        data: original.data,
    }
}

/// Link id derived from a link-request packet (same algorithm as [`crate::destination::link::LinkId`]'s
/// `From<&Packet>` when `std` enables `destination::link`).
pub fn link_id_from_link_request_packet(packet: &Packet) -> AddressHash {
    let data = packet.data.as_slice();
    let data_diff = if data.len() > PUBLIC_KEY_LENGTH * 2 {
        data.len() - PUBLIC_KEY_LENGTH * 2
    } else {
        0
    };

    let hashable_data = &data[..data.len() - data_diff];

    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(&[packet.header.to_meta() & 0b00001111])
            .chain_update(packet.destination.as_slice())
            .chain_update(&[packet.context as u8])
            .chain_update(hashable_data)
            .finalize()
            .into(),
    ))
}

/// Row mirroring [`crate::transport::link_table::LinkEntry`] for intermediate registration + proof back-prop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntermediateLinkEntry {
    pub link_id: AddressHash,
    pub next_hop: AddressHash,
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
}

/// Register an intermediate link (std [`crate::transport::link_table::LinkTable::add`]).
///
/// Returns `true` if inserted, `false` if this link id was already present.
pub fn try_register_intermediate_link_entry(
    table: &mut Vec<IntermediateLinkEntry>,
    max_entries: usize,
    link_request: &Packet,
    destination: AddressHash,
    received_from: AddressHash,
    next_hop: AddressHash,
    next_hop_iface: AddressHash,
) -> bool {
    let link_id = link_id_from_link_request_packet(link_request);
    if table.iter().any(|e| e.link_id == link_id) {
        return false;
    }
    let taken_hops = link_request.header.hops.saturating_add(1);
    table.push(IntermediateLinkEntry {
        link_id,
        next_hop,
        next_hop_iface,
        received_from,
        original_destination: destination,
        taken_hops,
        remaining_hops: 0,
        validated: false,
    });
    while table.len() > max_entries && !table.is_empty() {
        let _ = table.remove(0);
    }
    true
}

/// Build the propagated proof packet (std `send_backwards` in `link_table.rs`).
pub fn build_link_proof_propagation_packet(
    packet: &Packet,
    transport_next_hop: AddressHash,
) -> Packet {
    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            hops: packet.header.hops.saturating_add(1),
            ..packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(transport_next_hop),
        context: packet.context,
        data: packet.data,
    }
}

/// Apply a proof to an intermediate link entry (std [`crate::transport::link_table::LinkTable::handle_proof`]).
pub fn intermediate_link_table_apply_proof(
    table: &mut [IntermediateLinkEntry],
    proof: &Packet,
) -> Option<(Packet, AddressHash)> {
    for entry in table.iter_mut() {
        if entry.link_id != proof.destination {
            continue;
        }
        entry.remaining_hops = proof.header.hops;
        entry.validated = true;
        let packet = build_link_proof_propagation_packet(proof, entry.next_hop);
        return Some((packet, entry.received_from));
    }
    None
}

/// Link-table keepalive back-propagation (std [`crate::transport::link_table::LinkTable::handle_keepalive`]).
pub fn intermediate_link_table_handle_keepalive(
    table: &[IntermediateLinkEntry],
    packet: &Packet,
) -> Option<(Packet, AddressHash)> {
    for entry in table.iter() {
        if entry.link_id != packet.destination {
            continue;
        }
        let packet_out = build_link_proof_propagation_packet(packet, entry.next_hop);
        return Some((packet_out, entry.received_from));
    }
    None
}

/// Runtime-agnostic decision for fixed-destination dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedDestinationRoute {
    PathRequestHandler,
    Unhandled,
}

/// Decide if packet should be handled by fixed-destination path-request logic.
pub fn decide_fixed_destination_route(
    packet_destination: &AddressHash,
    fixed_dest_path_requests: &AddressHash,
) -> FixedDestinationRoute {
    if packet_destination == fixed_dest_path_requests {
        FixedDestinationRoute::PathRequestHandler
    } else {
        FixedDestinationRoute::Unhandled
    }
}

/// Build the canonical fixed destination used for path-request handling.
pub fn path_request_fixed_destination() -> AddressHash {
    PlainInputDestination::new(
        EmptyIdentity {},
        DestinationName::new("rnstransport", "path.request"),
    )
    .desc
    .address_hash
}

/// Runtime-agnostic decision for handling path requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestRoute {
    LocalDestinationResponse,
    ScheduleRemoteResponse,
    RecursiveBroadcast,
    DropCircular,
}

/// Shared path-request execution intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestExecutionIntent {
    LocalDestinationResponse,
    ScheduleRemoteResponse { hops: u8 },
    RecursiveBroadcast,
    DropCircular,
}

/// Shared action shape for path-request handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestAction {
    LocalDestinationResponse {
        ingress_iface: AddressHash,
    },
    ScheduleRemoteResponse {
        destination: AddressHash,
        ingress_iface: AddressHash,
        hops: u8,
    },
    RecursiveBroadcast {
        destination: AddressHash,
        exclude_iface: AddressHash,
    },
    DropCircular {
        destination: AddressHash,
    },
}

/// Shared helper for extracting recursive-broadcast egress iface from action.
pub fn recursive_broadcast_exclude_iface(action: PathRequestAction) -> Option<AddressHash> {
    match action {
        PathRequestAction::RecursiveBroadcast { exclude_iface, .. } => Some(exclude_iface),
        _ => None,
    }
}

pub enum StagedPathRequestEgressDecision {
    EmitRecursive { exclude_iface: AddressHash },
    CountOnly,
    None,
}

/// Shared Stage D policy for mapping path-request action to staged egress behavior.
pub fn decide_staged_path_request_egress(
    action: PathRequestAction,
    announce_triggered: bool,
) -> StagedPathRequestEgressDecision {
    if let Some(exclude_iface) = recursive_broadcast_exclude_iface(action) {
        StagedPathRequestEgressDecision::EmitRecursive { exclude_iface }
    } else if matches!(action, PathRequestAction::ScheduleRemoteResponse { .. })
        && announce_triggered
    {
        StagedPathRequestEgressDecision::CountOnly
    } else {
        StagedPathRequestEgressDecision::None
    }
}

/// Shared normalized inputs for path-request action decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRequestDecisionInput {
    pub request_destination: AddressHash,
    pub ingress_iface: AddressHash,
    pub requesting_transport: Option<AddressHash>,
    pub entry_received_from: Option<AddressHash>,
    pub has_local_destination: bool,
    pub retransmit_enabled: bool,
    pub known_hops: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRequestStateObservation {
    pub entry_received_from: Option<AddressHash>,
    pub known_hops: Option<u8>,
}

pub fn lookup_path_request_state(
    request_destination: AddressHash,
    received_from_entries: &[(AddressHash, AddressHash)],
    known_hops_entries: &[(AddressHash, u8)],
) -> PathRequestStateObservation {
    let entry_received_from = received_from_entries
        .iter()
        .find(|(destination, _)| *destination == request_destination)
        .map(|(_, recv)| *recv);
    let known_hops = known_hops_entries
        .iter()
        .find(|(destination, _)| *destination == request_destination)
        .map(|(_, hops)| *hops);
    PathRequestStateObservation {
        entry_received_from,
        known_hops,
    }
}

pub fn build_path_request_decision_input(
    request_destination: AddressHash,
    ingress_iface: AddressHash,
    requesting_transport: Option<AddressHash>,
    has_local_destination: bool,
    retransmit_enabled: bool,
    observation: PathRequestStateObservation,
) -> PathRequestDecisionInput {
    PathRequestDecisionInput {
        request_destination,
        ingress_iface,
        requesting_transport,
        entry_received_from: observation.entry_received_from,
        has_local_destination,
        retransmit_enabled,
        known_hops: observation.known_hops,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLifecycleTransition {
    AddPending,
    Activate,
    None,
}

/// Shared Stage D link lifecycle transition helper.
pub fn decide_link_lifecycle_transition(
    action: IngressAction,
    destination_requested_link_proof: bool,
    in_link_already_exists: bool,
    pending_link_exists: bool,
) -> LinkLifecycleTransition {
    match action {
        IngressAction::LinkRequest => match decide_in_link_registration_action(
            destination_requested_link_proof,
            in_link_already_exists,
        ) {
            InLinkRegistrationAction::CreateAndStore => LinkLifecycleTransition::AddPending,
            InLinkRegistrationAction::Skip => LinkLifecycleTransition::None,
        },
        IngressAction::Proof => match decide_proof_link_followup(pending_link_exists) {
            ProofLinkFollowup::SendRtt => LinkLifecycleTransition::Activate,
            ProofLinkFollowup::NoOp => LinkLifecycleTransition::None,
        },
        IngressAction::Announce | IngressAction::Data => LinkLifecycleTransition::None,
    }
}

/// Decide if a path request loops back to where it came from.
pub fn is_circular_path_request(
    requesting_transport: Option<&AddressHash>,
    entry_received_from: Option<&AddressHash>,
) -> bool {
    matches!(
        (requesting_transport, entry_received_from),
        (Some(requestor), Some(received_from)) if requestor == received_from
    )
}

/// Determine the route for a decoded path request.
pub fn decide_path_request_route(
    has_local_destination: bool,
    retransmit_enabled: bool,
    has_known_path: bool,
    is_circular_request: bool,
) -> PathRequestRoute {
    if has_local_destination {
        PathRequestRoute::LocalDestinationResponse
    } else if retransmit_enabled && has_known_path {
        if is_circular_request {
            PathRequestRoute::DropCircular
        } else {
            PathRequestRoute::ScheduleRemoteResponse
        }
    } else {
        PathRequestRoute::RecursiveBroadcast
    }
}

/// Decide executable path-request intent from route inputs.
pub fn decide_path_request_execution_intent(
    has_local_destination: bool,
    retransmit_enabled: bool,
    known_hops: Option<u8>,
    is_circular_request: bool,
) -> PathRequestExecutionIntent {
    match decide_path_request_route(
        has_local_destination,
        retransmit_enabled,
        known_hops.is_some(),
        is_circular_request,
    ) {
        PathRequestRoute::LocalDestinationResponse => {
            PathRequestExecutionIntent::LocalDestinationResponse
        }
        PathRequestRoute::ScheduleRemoteResponse => {
            if let Some(hops) = known_hops {
                PathRequestExecutionIntent::ScheduleRemoteResponse { hops }
            } else {
                // Defensive fallback: route and hops should stay consistent.
                PathRequestExecutionIntent::RecursiveBroadcast
            }
        }
        PathRequestRoute::RecursiveBroadcast => PathRequestExecutionIntent::RecursiveBroadcast,
        PathRequestRoute::DropCircular => PathRequestExecutionIntent::DropCircular,
    }
}

/// Decide concrete path-request action from shared intent inputs.
pub fn decide_path_request_action(
    request_destination: AddressHash,
    ingress_iface: AddressHash,
    has_local_destination: bool,
    retransmit_enabled: bool,
    known_hops: Option<u8>,
    is_circular_request: bool,
) -> PathRequestAction {
    match decide_path_request_execution_intent(
        has_local_destination,
        retransmit_enabled,
        known_hops,
        is_circular_request,
    ) {
        PathRequestExecutionIntent::LocalDestinationResponse => {
            PathRequestAction::LocalDestinationResponse { ingress_iface }
        }
        PathRequestExecutionIntent::ScheduleRemoteResponse { hops } => {
            PathRequestAction::ScheduleRemoteResponse {
                destination: request_destination,
                ingress_iface,
                hops,
            }
        }
        PathRequestExecutionIntent::RecursiveBroadcast => PathRequestAction::RecursiveBroadcast {
            destination: request_destination,
            exclude_iface: ingress_iface,
        },
        PathRequestExecutionIntent::DropCircular => PathRequestAction::DropCircular {
            destination: request_destination,
        },
    }
}

/// Decide path-request action from transport-state-style inputs.
///
/// This helper keeps std and no-std aligned by deriving circular-request
/// handling inside shared policy code.
pub fn decide_path_request_action_from_state(
    request_destination: AddressHash,
    ingress_iface: AddressHash,
    requesting_transport: Option<&AddressHash>,
    entry_received_from: Option<&AddressHash>,
    has_local_destination: bool,
    retransmit_enabled: bool,
    known_hops: Option<u8>,
) -> PathRequestAction {
    let is_circular_request = is_circular_path_request(requesting_transport, entry_received_from);
    decide_path_request_action(
        request_destination,
        ingress_iface,
        has_local_destination,
        retransmit_enabled,
        known_hops,
        is_circular_request,
    )
}

/// Decide path-request action from normalized input shape.
pub fn decide_path_request_action_from_input(input: PathRequestDecisionInput) -> PathRequestAction {
    decide_path_request_action_from_state(
        input.request_destination,
        input.ingress_iface,
        input.requesting_transport.as_ref(),
        input.entry_received_from.as_ref(),
        input.has_local_destination,
        input.retransmit_enabled,
        input.known_hops,
    )
}

/// Stage D synthetic payload marker used to emulate path-request ingress/egress.
pub const STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD: &[u8] = b"stage-d-synth-path-request";

/// Shared classification for path-request packets.
///
/// For protocol packets this is `Data` + `Request` context.
/// Stage D synthetic flows additionally allow the dedicated marker payload.
pub fn is_path_request_packet(
    packet_type: PacketType,
    context: PacketContext,
    payload: &[u8],
) -> bool {
    packet_type == PacketType::Data
        && (context == PacketContext::Request || payload == STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD)
}

/// Shared gate for fixed-destination path-request handling.
///
/// This is the exact condition both std transport and embedded Stage D should use
/// before treating an ingress packet as "fixed destination already handled".
pub fn should_handle_fixed_destination_path_request(
    packet_destination: &AddressHash,
    fixed_dest_path_requests: &AddressHash,
    packet_type: PacketType,
    context: PacketContext,
    payload: &[u8],
) -> bool {
    matches!(
        decide_fixed_destination_route(packet_destination, fixed_dest_path_requests),
        FixedDestinationRoute::PathRequestHandler
    ) && is_path_request_packet(packet_type, context, payload)
}

/// Runtime-agnostic final duplicate-filter outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateOutcome {
    AcceptNew,
    AcceptAllowedDuplicate,
    DropDuplicate,
}

/// Decide whether duplicate packets of this kind should still be accepted.
pub fn allow_duplicate_packet(
    packet_type: PacketType,
    context: PacketContext,
    in_link_pending_proof: bool,
) -> bool {
    match packet_type {
        PacketType::Announce => true,
        PacketType::LinkRequest => true,
        PacketType::Data => context == PacketContext::KeepAlive,
        PacketType::Proof => context == PacketContext::LinkRequestProof && in_link_pending_proof,
    }
}

/// Combine cache state and duplicate policy into a final handling outcome.
pub fn duplicate_outcome(is_new: bool, allow_duplicate: bool) -> DuplicateOutcome {
    if is_new {
        DuplicateOutcome::AcceptNew
    } else if allow_duplicate {
        DuplicateOutcome::AcceptAllowedDuplicate
    } else {
        DuplicateOutcome::DropDuplicate
    }
}

/// Shared duplicate decision for a packet after cache update.
///
/// `is_new` should be the result of the runtime cache update operation.
pub fn decide_duplicate_outcome(
    packet_type: PacketType,
    context: PacketContext,
    in_link_pending_proof: bool,
    is_new: bool,
) -> DuplicateOutcome {
    let allow_duplicate = allow_duplicate_packet(packet_type, context, in_link_pending_proof);
    duplicate_outcome(is_new, allow_duplicate)
}

/// Shared ingress policy composition.
///
/// This combines duplicate policy and ingress routing policy into one helper so
/// std and embedded runtimes can follow exactly the same decision sequence.
pub fn decide_ingress_with_duplicate_policy(
    packet_type: PacketType,
    context: PacketContext,
    fixed_destination_handled: bool,
    in_link_pending_proof: bool,
    is_new: bool,
    broadcast_enabled: bool,
) -> (DuplicateOutcome, IngressDecision) {
    let duplicate = decide_duplicate_outcome(packet_type, context, in_link_pending_proof, is_new);
    let decision = decide_ingress(
        packet_type,
        fixed_destination_handled,
        duplicate == DuplicateOutcome::DropDuplicate,
        broadcast_enabled,
    );
    (duplicate, decision)
}

/// Shared ingress decision helper when duplicate outcome is already known.
pub fn decide_ingress_from_duplicate_outcome(
    packet_type: PacketType,
    fixed_destination_handled: bool,
    duplicate: DuplicateOutcome,
    broadcast_enabled: bool,
) -> IngressDecision {
    decide_ingress(
        packet_type,
        fixed_destination_handled,
        duplicate == DuplicateOutcome::DropDuplicate,
        broadcast_enabled,
    )
}

/// Decide ingress from normalized input shape.
pub fn decide_ingress_from_input(input: IngressDecisionInput) -> IngressDecision {
    decide_ingress_from_duplicate_outcome(
        input.packet_type,
        input.fixed_destination_handled,
        input.duplicate,
        input.broadcast_enabled,
    )
}

/// Gate for when transport should compute the in-link pending proof condition.
pub fn should_consider_in_link_pending_proof(
    packet_type: PacketType,
    context: PacketContext,
) -> bool {
    packet_type == PacketType::Proof && context == PacketContext::LinkRequestProof
}

/// Shared gate for whether a packet should be treated as "in-link pending proof".
///
/// `destination_pending` should be computed by runtime-specific state lookup.
pub fn is_in_link_pending_proof(
    packet_type: PacketType,
    context: PacketContext,
    destination_pending: bool,
) -> bool {
    should_consider_in_link_pending_proof(packet_type, context) && destination_pending
}

/// Runtime-agnostic decision for how to treat an announce for destination discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceDiscoveryRoute {
    IgnoreKnownDestination,
    TrackPathOnly,
    RegisterAndTrackPath,
}

/// Runtime-agnostic action for announce retransmit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceRetransmitAction {
    SendGeneratedPacket,
    Skip,
}

/// Decide announce discovery path based on existing destination knowledge.
pub fn decide_announce_discovery_route(
    destination_known: bool,
    has_single_out_destination: bool,
) -> AnnounceDiscoveryRoute {
    if destination_known {
        AnnounceDiscoveryRoute::IgnoreKnownDestination
    } else if has_single_out_destination {
        AnnounceDiscoveryRoute::TrackPathOnly
    } else {
        AnnounceDiscoveryRoute::RegisterAndTrackPath
    }
}

/// Decide if announce retransmit packet should be sent.
pub fn decide_announce_retransmit_action(
    retransmit_enabled: bool,
    has_generated_packet: bool,
) -> AnnounceRetransmitAction {
    if retransmit_enabled && has_generated_packet {
        AnnounceRetransmitAction::SendGeneratedPacket
    } else {
        AnnounceRetransmitAction::Skip
    }
}

/// Decide whether keepalive-response handling path should run.
pub fn should_handle_keepalive_response(context: PacketContext, first_byte: Option<u8>) -> bool {
    context == PacketContext::KeepAlive && first_byte == Some(0xFE)
}

/// Runtime-agnostic meaning of keepalive payload byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepAliveKind {
    Request,
    Response,
    Unknown,
}

/// Decode keepalive marker byte to semantic meaning.
pub fn classify_keepalive_byte(byte: Option<u8>) -> KeepAliveKind {
    match byte {
        Some(0xFF) => KeepAliveKind::Request,
        Some(0xFE) => KeepAliveKind::Response,
        _ => KeepAliveKind::Unknown,
    }
}

/// Decide whether enough time passed to retransmit "old announces".
pub fn decide_old_announce_retransmit(
    elapsed: Duration,
    interval_old_announces_retransmit: Duration,
) -> bool {
    elapsed > interval_old_announces_retransmit
}

/// Runtime-agnostic route for link-destination data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDestinationDataRoute {
    ProcessLocalOnly,
    ProcessLocalAndForward,
}

/// Decide high-level handling route for link-destination packets.
pub fn decide_link_destination_data_route(
    has_link_table_destination: bool,
) -> LinkDestinationDataRoute {
    if has_link_table_destination {
        LinkDestinationDataRoute::ProcessLocalAndForward
    } else {
        LinkDestinationDataRoute::ProcessLocalOnly
    }
}

/// Runtime-agnostic local follow-up for proof packets on out-links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofLinkFollowup {
    SendRtt,
    NoOp,
}

/// Decide local follow-up based on whether proof activated the link.
pub fn decide_proof_link_followup(link_activated: bool) -> ProofLinkFollowup {
    if link_activated {
        ProofLinkFollowup::SendRtt
    } else {
        ProofLinkFollowup::NoOp
    }
}

/// Follow-up action transport should perform after link-table proof handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofHandleFollowup {
    SendDirect { packet: Packet, iface: AddressHash },
    NoOp,
}

/// Decide transport follow-up based on optional proof packet produced by link-table logic.
pub fn decide_proof_handle_followup(
    maybe_packet: Option<(Packet, AddressHash)>,
) -> ProofHandleFollowup {
    match maybe_packet {
        Some((packet, iface)) => ProofHandleFollowup::SendDirect { packet, iface },
        None => ProofHandleFollowup::NoOp,
    }
}

/// Follow-up action transport should perform after `link.handle_packet(...)`.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkHandleFollowup {
    /// Send a keep-alive response back to the peer.
    SendKeepAliveResponse,
    /// Send the proof packet back into transport.
    SendProof(Packet),
    /// No additional transport action is required.
    NoOp,
}

/// Decide transport follow-up based on the result returned by `Link::handle_packet`.
#[cfg(feature = "std")]
pub fn decide_link_handle_followup(result: LinkHandleResult) -> LinkHandleFollowup {
    match result {
        LinkHandleResult::KeepAlive => LinkHandleFollowup::SendKeepAliveResponse,
        LinkHandleResult::MessageReceived(Some(proof)) => LinkHandleFollowup::SendProof(proof),
        _ => LinkHandleFollowup::NoOp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_request_proof_hint_matches_link_request_to_local() {
        assert!(link_request_destination_requests_proof(
            PacketType::LinkRequest,
            true
        ));
        assert!(!link_request_destination_requests_proof(
            PacketType::LinkRequest,
            false
        ));
        assert!(!link_request_destination_requests_proof(
            PacketType::Data,
            true
        ));
    }

    #[test]
    fn link_request_route_three_way_split() {
        assert_eq!(
            decide_link_request_route(true, false),
            LinkRequestRoute::LocalDestination
        );
        assert_eq!(
            decide_link_request_route(false, true),
            LinkRequestRoute::Intermediate
        );
        assert_eq!(
            decide_link_request_route(false, false),
            LinkRequestRoute::DropUnknown
        );
    }

    #[test]
    fn path_cache_lookup_matches_destination() {
        let d = AddressHash::new_empty();
        assert!(path_cache_lookup_next_hop(&[], d).is_none());
        let a = AddressHash::new([1u8; 16]);
        let b = AddressHash::new([2u8; 16]);
        let c = AddressHash::new([3u8; 16]);
        let cache = [(a, b), (c, a)];
        assert_eq!(path_cache_lookup_next_hop(&cache, a), Some(b));
        assert_eq!(path_cache_lookup_next_hop(&cache, c), Some(a));
        assert!(path_cache_lookup_next_hop(&cache, b).is_none());
    }

    #[test]
    fn build_packet_forward_type2_sets_transport_and_header() {
        let mut p = Packet::default();
        p.header.packet_type = PacketType::Data;
        p.header.hops = 3;
        p.destination = AddressHash::new([9u8; 16]);
        let next = AddressHash::new([7u8; 16]);
        let out = build_packet_forward_type2(&p, next);
        assert_eq!(out.header.header_type, HeaderType::Type2);
        assert_eq!(out.header.hops, 4);
        assert_eq!(out.transport, Some(next));
        assert_eq!(out.destination, p.destination);
    }

    #[test]
    fn intermediate_link_register_skips_duplicate_link_id() {
        use crate::packet::PacketDataBuffer;

        let mut t = Vec::new();
        let mut lr = Packet::default();
        lr.header.packet_type = PacketType::LinkRequest;
        lr.data = PacketDataBuffer::new_from_slice(&[0u8; 64]);
        let dst = AddressHash::new([4u8; 16]);
        lr.destination = dst;
        assert!(try_register_intermediate_link_entry(
            &mut t,
            8,
            &lr,
            dst,
            AddressHash::new([5u8; 16]),
            AddressHash::new([6u8; 16]),
            AddressHash::new([7u8; 16]),
        ));
        assert!(!try_register_intermediate_link_entry(
            &mut t,
            8,
            &lr,
            dst,
            AddressHash::new([1u8; 16]),
            AddressHash::new([2u8; 16]),
            AddressHash::new([3u8; 16]),
        ));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn intermediate_link_proof_propagates() {
        use crate::packet::PacketDataBuffer;

        let mut t = Vec::new();
        let mut lr = Packet::default();
        lr.header.packet_type = PacketType::LinkRequest;
        lr.data = PacketDataBuffer::new_from_slice(&[3u8; 64]);
        let dst = AddressHash::new([8u8; 16]);
        lr.destination = dst;
        try_register_intermediate_link_entry(
            &mut t,
            8,
            &lr,
            dst,
            AddressHash::new([10u8; 16]),
            AddressHash::new([11u8; 16]),
            AddressHash::new([12u8; 16]),
        );
        let lid = link_id_from_link_request_packet(&lr);
        let mut proof = Packet::default();
        proof.header.packet_type = PacketType::Proof;
        proof.destination = lid;
        proof.header.hops = 2;
        let got = intermediate_link_table_apply_proof(&mut t, &proof);
        assert!(got.is_some());
        let (out_pkt, iface) = got.unwrap();
        assert_eq!(iface, AddressHash::new([10u8; 16]));
        assert_eq!(out_pkt.transport, Some(AddressHash::new([11u8; 16])));
        assert!(t[0].validated);
        assert_eq!(t[0].remaining_hops, 2);
    }

    #[test]
    fn intermediate_link_keepalive_propagates() {
        use crate::packet::PacketContext;
        use crate::packet::PacketDataBuffer;

        let mut lr = Packet::default();
        lr.header.packet_type = PacketType::LinkRequest;
        lr.data = PacketDataBuffer::new_from_slice(&[5u8; 64]);
        let dst = AddressHash::new([0xadu8; 16]);
        lr.destination = dst;
        let mut t = Vec::new();
        try_register_intermediate_link_entry(
            &mut t,
            8,
            &lr,
            dst,
            AddressHash::new([0xc0u8; 16]),
            AddressHash::new([0xd0u8; 16]),
            AddressHash::new([0xe0u8; 16]),
        );
        let lid = link_id_from_link_request_packet(&lr);
        let mut ka = Packet::default();
        ka.header.packet_type = PacketType::Data;
        ka.header.destination_type = crate::packet::DestinationType::Link;
        ka.destination = lid;
        ka.context = PacketContext::KeepAlive;
        ka.data = PacketDataBuffer::new_from_slice(&[0xFEu8]);
        let got = intermediate_link_table_handle_keepalive(&t, &ka);
        assert!(got.is_some());
        let (out, iface) = got.unwrap();
        assert_eq!(iface, AddressHash::new([0xc0u8; 16]));
        assert_eq!(out.transport, Some(AddressHash::new([0xd0u8; 16])));
        assert_eq!(out.header.header_type, HeaderType::Type2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn link_id_from_packet_matches_std_destination_link() {
        use crate::destination::link::LinkId;
        use crate::packet::PacketDataBuffer;

        let mut p = Packet::default();
        p.header.packet_type = PacketType::LinkRequest;
        p.data = PacketDataBuffer::new_from_slice(&[9u8; 80]);
        p.destination = AddressHash::new([0xabu8; 16]);
        assert_eq!(link_id_from_link_request_packet(&p), LinkId::from(&p));
    }
}
