use crate::{
    hash::AddressHash,
    destination::link::LinkStatus,
    destination::link::LinkHandleResult,
    packet::{Packet, PacketContext, PacketType},
};
use core::time::Duration;

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

/// Explanation for ingress decision paths, used for traceability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressReason {
    FixedDestinationMatched,
    DuplicateFiltered,
    FreshPacketDispatched,
}

/// Final duplicate-filter outcome after cache update and policy checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateOutcome {
    AcceptNew,
    AcceptAllowedDuplicate,
    DropDuplicate,
}

/// Runtime-agnostic route decision for link request packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRequestRoute {
    LocalDestination,
    Intermediate,
    DropUnknown,
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

/// Runtime-agnostic maintenance action for input links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InLinkMaintenanceAction {
    MarkStale,
    TeardownAndRemove,
    NoOp,
}

/// Decide maintenance action for an input link based on state and elapsed time.
pub fn decide_in_link_maintenance_action(
    status: LinkStatus,
    elapsed: Duration,
    input_stale_after: Duration,
    input_close_after: Duration,
) -> InLinkMaintenanceAction {
    match status {
        LinkStatus::Active if elapsed > input_stale_after => InLinkMaintenanceAction::MarkStale,
        LinkStatus::Stale if elapsed > input_stale_after + input_close_after => {
            InLinkMaintenanceAction::TeardownAndRemove
        }
        _ => InLinkMaintenanceAction::NoOp,
    }
}

/// Runtime-agnostic maintenance action for output links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutLinkMaintenanceAction {
    MarkStale,
    Restart,
    TeardownAndRemove,
    RepeatRequest,
    CloseAndRemove,
    NoOp,
}

/// Decide maintenance action for an output link based on state and elapsed time.
pub fn decide_out_link_maintenance_action(
    status: LinkStatus,
    elapsed: Duration,
    restart_outlinks: bool,
    output_stale_after: Duration,
    output_close_after: Duration,
    output_restart_after: Duration,
    output_repeat_after: Duration,
) -> OutLinkMaintenanceAction {
    match status {
        LinkStatus::Active if elapsed > output_stale_after => OutLinkMaintenanceAction::MarkStale,
        LinkStatus::Stale if restart_outlinks && elapsed > output_restart_after => {
            OutLinkMaintenanceAction::Restart
        }
        LinkStatus::Stale if !restart_outlinks && elapsed > output_stale_after + output_close_after => {
            OutLinkMaintenanceAction::TeardownAndRemove
        }
        LinkStatus::Pending if elapsed > output_repeat_after => OutLinkMaintenanceAction::RepeatRequest,
        LinkStatus::Closed => OutLinkMaintenanceAction::CloseAndRemove,
        _ => OutLinkMaintenanceAction::NoOp,
    }
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

/// Runtime-agnostic decision for handling path requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRequestRoute {
    LocalDestinationResponse,
    ScheduleRemoteResponse,
    RecursiveBroadcast,
    DropCircular,
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

/// Runtime-agnostic route decision for single-destination data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleDataRoute {
    DeliverLocal,
    Forward,
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

/// Decide whether a single-destination packet is for us or should be forwarded.
pub fn decide_single_data_route(has_local_destination: bool) -> SingleDataRoute {
    if has_local_destination {
        SingleDataRoute::DeliverLocal
    } else {
        SingleDataRoute::Forward
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

/// What follow-up action `transport.rs` should perform after the link-table returns an optional proof packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofHandleFollowup {
    SendDirect { packet: Packet, iface: AddressHash },
    NoOp,
}

/// Decide transport follow-up based on optional proof packet produced by link-table logic.
///
/// - `Some((packet, iface))` => `SendDirect`
/// - `None` => `NoOp`
pub fn decide_proof_handle_followup(
    maybe_packet: Option<(Packet, AddressHash)>,
) -> ProofHandleFollowup {
    match maybe_packet {
        Some((packet, iface)) => ProofHandleFollowup::SendDirect { packet, iface },
        None => ProofHandleFollowup::NoOp,
    }
}

/// What follow-up action `transport.rs` should perform after `link.handle_packet(...)`.
///
/// This is deterministic decision logic only:
/// - It has no async code
/// - It has no side effects
/// - It only translates `LinkHandleResult` -> "which action should happen"
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
///
/// Mapping:
/// - `KeepAlive` -> `SendKeepAliveResponse`
/// - `MessageReceived(Some(proof))` -> `SendProof(proof)`
/// - everything else -> `NoOp`
pub fn decide_link_handle_followup(result: LinkHandleResult) -> LinkHandleFollowup {
    match result {
        LinkHandleResult::KeepAlive => LinkHandleFollowup::SendKeepAliveResponse,
        LinkHandleResult::MessageReceived(Some(proof)) => LinkHandleFollowup::SendProof(proof),
        _ => LinkHandleFollowup::NoOp,
    }
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

/// Decide whether keepalive-response handling path should run.
pub fn should_handle_keepalive_response(context: PacketContext, first_byte: Option<u8>) -> bool {
    context == PacketContext::KeepAlive
        && classify_keepalive_byte(first_byte) == KeepAliveKind::Response
}

/// Decide whether enough time passed to retransmit "old announces".
///
/// This is pure timing policy only: it compares an already-computed elapsed
/// duration against the configured retransmit interval.
pub fn decide_old_announce_retransmit(
    elapsed: Duration,
    interval_old_announces_retransmit: Duration,
) -> bool {
    elapsed > interval_old_announces_retransmit
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

/// Decide whether duplicate packets of this kind should still be accepted.
///
/// Some protocol packets are intentionally allowed through even when they are
/// duplicates (for example link handshake/proof edge-cases and keepalive data).
pub fn allow_duplicate_packet(
    packet_type: PacketType,
    context: PacketContext,
    in_link_pending_proof: bool,
) -> bool {
    match packet_type {
        PacketType::Announce => true,
        PacketType::LinkRequest => true,
        PacketType::Data => context == PacketContext::KeepAlive,
        PacketType::Proof => {
            context == PacketContext::LinkRequestProof && in_link_pending_proof
        }
    }
}

/// Gate for when transport should compute the "in-link pending proof" condition.
///
/// This is extracted so transport doesn't have to embed the protocol rule
/// `packet_type == Proof && context == LinkRequestProof` directly.
pub fn should_consider_in_link_pending_proof(
    packet_type: PacketType,
    context: PacketContext,
) -> bool {
    packet_type == PacketType::Proof && context == PacketContext::LinkRequestProof
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

/// Runtime-agnostic classification for link data packet handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDataAction {
    Message,
    KeepAliveRequest,
    KeepAliveResponse,
    Rtt,
    Close,
    Other,
}

/// Decide how a link data packet should be interpreted.
pub fn classify_link_data(context: PacketContext, first_byte: Option<u8>) -> LinkDataAction {
    match context {
        PacketContext::None => LinkDataAction::Message,
        PacketContext::KeepAlive => match first_byte {
            Some(0xFF) => LinkDataAction::KeepAliveRequest,
            Some(0xFE) => LinkDataAction::KeepAliveResponse,
            _ => LinkDataAction::Other,
        },
        PacketContext::LinkRTT => LinkDataAction::Rtt,
        PacketContext::LinkClose => LinkDataAction::Close,
        _ => LinkDataAction::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        allow_duplicate_packet, classify_link_data, decide_ingress, duplicate_outcome,
        decide_announce_discovery_route, decide_announce_retransmit_action,
        decide_fixed_destination_route, decide_link_request_route, DuplicateOutcome,
        IngressAction, IngressDecision, IngressReason, KeepAliveKind, LinkDataAction,
        LinkRequestRoute, PathRequestRoute, SingleDataRoute,
        LinkDestinationDataRoute, AnnounceDiscoveryRoute, AnnounceRetransmitAction,
        FixedDestinationRoute, InLinkRegistrationAction, IntermediateLinkRequestAction,
        InLinkMaintenanceAction, OutLinkMaintenanceAction,
        decide_in_link_registration_action, decide_intermediate_link_request_action,
        decide_in_link_maintenance_action, decide_out_link_maintenance_action,
        decide_link_destination_data_route, decide_path_request_route,
        decide_proof_link_followup, decide_proof_handle_followup, decide_single_data_route,
        decide_link_handle_followup,
        is_circular_path_request, ProofLinkFollowup, LinkHandleFollowup,
        ProofHandleFollowup,
        classify_keepalive_byte, should_handle_keepalive_response,
        should_consider_in_link_pending_proof,
        decide_old_announce_retransmit,
    };
    use crate::hash::AddressHash;
    use crate::packet::{Packet, PacketContext, PacketType};
    use crate::destination::link::LinkStatus;
    use crate::destination::link::LinkHandleResult;
    use core::time::Duration;

    #[test]
    fn ingress_drops_duplicate_after_fixed_check() {
        let decision = decide_ingress(PacketType::Data, false, true, true);
        assert_eq!(
            decision,
            IngressDecision::DropDuplicate(IngressReason::DuplicateFiltered)
        );
    }

    #[test]
    fn ingress_short_circuits_fixed_destinations() {
        let decision = decide_ingress(PacketType::Proof, true, false, true);
        assert_eq!(
            decision,
            IngressDecision::HandleFixedDestination(IngressReason::FixedDestinationMatched)
        );
    }

    #[test]
    fn ingress_rebroadcasts_non_announce_when_enabled() {
        let decision = decide_ingress(PacketType::Data, false, false, true);
        assert_eq!(
            decision,
            IngressDecision::Dispatch {
                rebroadcast: true,
                action: IngressAction::Data,
                reason: IngressReason::FreshPacketDispatched
            }
        );
    }

    #[test]
    fn ingress_does_not_rebroadcast_announces() {
        let decision = decide_ingress(PacketType::Announce, false, false, true);
        assert_eq!(
            decision,
            IngressDecision::Dispatch {
                rebroadcast: false,
                action: IngressAction::Announce,
                reason: IngressReason::FreshPacketDispatched
            }
        );
    }

    #[test]
    fn duplicate_policy_matches_current_protocol_rules() {
        assert!(allow_duplicate_packet(
            PacketType::Announce,
            PacketContext::None,
            false
        ));
        assert!(allow_duplicate_packet(
            PacketType::LinkRequest,
            PacketContext::None,
            false
        ));
        assert!(allow_duplicate_packet(
            PacketType::Data,
            PacketContext::KeepAlive,
            false
        ));
        assert!(!allow_duplicate_packet(
            PacketType::Data,
            PacketContext::None,
            false
        ));
        assert!(allow_duplicate_packet(
            PacketType::Proof,
            PacketContext::LinkRequestProof,
            true
        ));
        assert!(!allow_duplicate_packet(
            PacketType::Proof,
            PacketContext::LinkRequestProof,
            false
        ));
    }

    #[test]
    fn classify_link_data_variants() {
        assert_eq!(
            classify_link_data(PacketContext::None, None),
            LinkDataAction::Message
        );
        assert_eq!(
            classify_link_data(PacketContext::KeepAlive, Some(0xFF)),
            LinkDataAction::KeepAliveRequest
        );
        assert_eq!(
            classify_link_data(PacketContext::KeepAlive, Some(0xFE)),
            LinkDataAction::KeepAliveResponse
        );
        assert_eq!(
            classify_link_data(PacketContext::LinkRTT, None),
            LinkDataAction::Rtt
        );
        assert_eq!(
            classify_link_data(PacketContext::LinkClose, None),
            LinkDataAction::Close
        );
        assert_eq!(
            classify_link_data(PacketContext::KeepAlive, Some(0x01)),
            LinkDataAction::Other
        );
    }

    #[test]
    fn duplicate_outcome_matrix() {
        assert_eq!(duplicate_outcome(true, false), DuplicateOutcome::AcceptNew);
        assert_eq!(
            duplicate_outcome(false, true),
            DuplicateOutcome::AcceptAllowedDuplicate
        );
        assert_eq!(
            duplicate_outcome(false, false),
            DuplicateOutcome::DropDuplicate
        );
    }

    #[test]
    fn link_request_routing_priority() {
        assert_eq!(
            decide_link_request_route(true, true),
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
    fn in_link_registration_action_routing() {
        assert_eq!(
            decide_in_link_registration_action(true, false),
            InLinkRegistrationAction::CreateAndStore
        );
        assert_eq!(
            decide_in_link_registration_action(true, true),
            InLinkRegistrationAction::Skip
        );
        assert_eq!(
            decide_in_link_registration_action(false, false),
            InLinkRegistrationAction::Skip
        );
    }

    #[test]
    fn intermediate_link_request_action_routing() {
        assert_eq!(
            decide_intermediate_link_request_action(true),
            IntermediateLinkRequestAction::AddLinkTableAndForward
        );
        assert_eq!(
            decide_intermediate_link_request_action(false),
            IntermediateLinkRequestAction::Skip
        );
    }

    #[test]
    fn in_link_maintenance_actions() {
        assert_eq!(
            decide_in_link_maintenance_action(
                LinkStatus::Active,
                Duration::from_secs(11),
                Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            InLinkMaintenanceAction::MarkStale
        );
        assert_eq!(
            decide_in_link_maintenance_action(
                LinkStatus::Stale,
                Duration::from_secs(16),
                Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            InLinkMaintenanceAction::TeardownAndRemove
        );
        assert_eq!(
            decide_in_link_maintenance_action(
                LinkStatus::Pending,
                Duration::from_secs(100),
                Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            InLinkMaintenanceAction::NoOp
        );
    }

    #[test]
    fn out_link_maintenance_actions() {
        assert_eq!(
            decide_out_link_maintenance_action(
                LinkStatus::Active,
                Duration::from_secs(11),
                false,
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(20),
                Duration::from_secs(3),
            ),
            OutLinkMaintenanceAction::MarkStale
        );
        assert_eq!(
            decide_out_link_maintenance_action(
                LinkStatus::Stale,
                Duration::from_secs(21),
                true,
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(20),
                Duration::from_secs(3),
            ),
            OutLinkMaintenanceAction::Restart
        );
        assert_eq!(
            decide_out_link_maintenance_action(
                LinkStatus::Stale,
                Duration::from_secs(16),
                false,
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(20),
                Duration::from_secs(3),
            ),
            OutLinkMaintenanceAction::TeardownAndRemove
        );
        assert_eq!(
            decide_out_link_maintenance_action(
                LinkStatus::Pending,
                Duration::from_secs(4),
                false,
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(20),
                Duration::from_secs(3),
            ),
            OutLinkMaintenanceAction::RepeatRequest
        );
        assert_eq!(
            decide_out_link_maintenance_action(
                LinkStatus::Closed,
                Duration::from_secs(0),
                false,
                Duration::from_secs(10),
                Duration::from_secs(5),
                Duration::from_secs(20),
                Duration::from_secs(3),
            ),
            OutLinkMaintenanceAction::CloseAndRemove
        );
    }

    #[test]
    fn path_request_routing_priority() {
        assert_eq!(
            decide_path_request_route(true, true, true, true),
            PathRequestRoute::LocalDestinationResponse
        );
        assert_eq!(
            decide_path_request_route(false, true, true, false),
            PathRequestRoute::ScheduleRemoteResponse
        );
        assert_eq!(
            decide_path_request_route(false, true, true, true),
            PathRequestRoute::DropCircular
        );
        assert_eq!(
            decide_path_request_route(false, false, false, false),
            PathRequestRoute::RecursiveBroadcast
        );
    }

    #[test]
    fn circular_path_request_detection() {
        let a = AddressHash::new([1u8; 16]);
        let b = AddressHash::new([2u8; 16]);
        assert!(is_circular_path_request(Some(&a), Some(&a)));
        assert!(!is_circular_path_request(Some(&a), Some(&b)));
        assert!(!is_circular_path_request(None, Some(&a)));
        assert!(!is_circular_path_request(Some(&a), None));
    }

    #[test]
    fn announce_discovery_routing() {
        assert_eq!(
            decide_announce_discovery_route(true, false),
            AnnounceDiscoveryRoute::IgnoreKnownDestination
        );
        assert_eq!(
            decide_announce_discovery_route(false, true),
            AnnounceDiscoveryRoute::TrackPathOnly
        );
        assert_eq!(
            decide_announce_discovery_route(false, false),
            AnnounceDiscoveryRoute::RegisterAndTrackPath
        );
    }

    #[test]
    fn fixed_destination_routing() {
        let path_dest = AddressHash::new([3u8; 16]);
        let other_dest = AddressHash::new([4u8; 16]);
        assert_eq!(
            decide_fixed_destination_route(&path_dest, &path_dest),
            FixedDestinationRoute::PathRequestHandler
        );
        assert_eq!(
            decide_fixed_destination_route(&other_dest, &path_dest),
            FixedDestinationRoute::Unhandled
        );
    }

    #[test]
    fn announce_retransmit_action_routing() {
        assert_eq!(
            decide_announce_retransmit_action(true, true),
            AnnounceRetransmitAction::SendGeneratedPacket
        );
        assert_eq!(
            decide_announce_retransmit_action(true, false),
            AnnounceRetransmitAction::Skip
        );
        assert_eq!(
            decide_announce_retransmit_action(false, true),
            AnnounceRetransmitAction::Skip
        );
    }

    #[test]
    fn single_data_routing() {
        assert_eq!(
            decide_single_data_route(true),
            SingleDataRoute::DeliverLocal
        );
        assert_eq!(decide_single_data_route(false), SingleDataRoute::Forward);
    }

    #[test]
    fn proof_link_followup_decision() {
        assert_eq!(
            decide_proof_link_followup(true),
            ProofLinkFollowup::SendRtt
        );
        assert_eq!(
            decide_proof_link_followup(false),
            ProofLinkFollowup::NoOp
        );
    }

    #[test]
    fn link_handle_followup_decision() {
        // Table-driven test: easier to add new LinkHandleResult cases later.
        let proof = Packet::default();
        let cases: [(LinkHandleResult, LinkHandleFollowup); 4] = [
            (
                LinkHandleResult::KeepAlive,
                LinkHandleFollowup::SendKeepAliveResponse,
            ),
            (
                LinkHandleResult::MessageReceived(Some(proof)),
                LinkHandleFollowup::SendProof(proof),
            ),
            (
                LinkHandleResult::MessageReceived(None),
                LinkHandleFollowup::NoOp,
            ),
            (LinkHandleResult::Activated, LinkHandleFollowup::NoOp),
        ];

        for (input, expected) in cases {
            assert_eq!(decide_link_handle_followup(input), expected);
        }
    }

    #[test]
    fn in_link_pending_proof_candidate_gate() {
        assert!(should_consider_in_link_pending_proof(
            PacketType::Proof,
            PacketContext::LinkRequestProof
        ));
        assert!(!should_consider_in_link_pending_proof(
            PacketType::Data,
            PacketContext::LinkRequestProof
        ));
        assert!(!should_consider_in_link_pending_proof(
            PacketType::Proof,
            PacketContext::None
        ));
    }

    #[test]
    fn old_announce_retransmit_timing() {
        let interval = Duration::from_secs(60);
        assert!(!decide_old_announce_retransmit(
            Duration::from_secs(59),
            interval
        ));
        assert!(!decide_old_announce_retransmit(
            Duration::from_secs(60),
            interval
        ));
        assert!(decide_old_announce_retransmit(
            Duration::from_secs(61),
            interval
        ));
    }

    #[test]
    fn proof_handle_followup_decision() {
        let iface = AddressHash::new([7u8; 16]);
        let packet = Packet::default();

        assert_eq!(
            decide_proof_handle_followup(Some((packet, iface))),
            ProofHandleFollowup::SendDirect { packet, iface }
        );
        assert_eq!(
            decide_proof_handle_followup(None),
            ProofHandleFollowup::NoOp
        );
    }

    #[test]
    fn link_destination_data_routes() {
        assert_eq!(
            decide_link_destination_data_route(false),
            LinkDestinationDataRoute::ProcessLocalOnly
        );
        assert_eq!(
            decide_link_destination_data_route(true),
            LinkDestinationDataRoute::ProcessLocalAndForward
        );
    }

    #[test]
    fn classify_keepalive_values() {
        assert_eq!(classify_keepalive_byte(Some(0xFF)), KeepAliveKind::Request);
        assert_eq!(classify_keepalive_byte(Some(0xFE)), KeepAliveKind::Response);
        assert_eq!(classify_keepalive_byte(Some(0x01)), KeepAliveKind::Unknown);
        assert_eq!(classify_keepalive_byte(None), KeepAliveKind::Unknown);
    }

    #[test]
    fn keepalive_response_gate() {
        assert!(should_handle_keepalive_response(
            PacketContext::KeepAlive,
            Some(0xFE)
        ));
        assert!(!should_handle_keepalive_response(
            PacketContext::KeepAlive,
            Some(0xFF)
        ));
        assert!(!should_handle_keepalive_response(
            PacketContext::None,
            Some(0xFE)
        ));
    }
}
