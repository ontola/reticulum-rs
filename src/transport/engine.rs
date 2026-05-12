use crate::destination::link::LinkStatus;
use crate::packet::PacketContext;
use core::time::Duration;

// Compatibility re-exports: canonical policy now lives in `transport_engine`.
#[allow(unused_imports)]
pub use crate::transport_engine::{
    allow_duplicate_packet, build_path_request_decision_input, classify_keepalive_byte,
    decide_announce_discovery_route, decide_announce_retransmit_action, decide_duplicate_outcome,
    decide_fixed_destination_route, decide_in_link_registration_action, decide_ingress,
    decide_ingress_from_duplicate_outcome, decide_ingress_from_input,
    decide_ingress_with_duplicate_policy, decide_intermediate_link_request_action,
    decide_link_destination_data_route, decide_link_lifecycle_transition,
    decide_link_request_route, decide_old_announce_retransmit, decide_path_request_action,
    decide_path_request_action_from_input, decide_path_request_action_from_state,
    decide_path_request_execution_intent, decide_path_request_route, decide_proof_handle_followup,
    decide_proof_link_followup, decide_single_data_route, decide_staged_path_request_egress,
    duplicate_outcome, is_circular_path_request, is_in_link_pending_proof, is_path_request_packet,
    lookup_path_request_state, path_request_fixed_destination, recursive_broadcast_exclude_iface,
    should_consider_in_link_pending_proof, should_handle_fixed_destination_path_request,
    should_handle_keepalive_response, AnnounceDiscoveryRoute, AnnounceRetransmitAction,
    DuplicateOutcome, FixedDestinationRoute, InLinkRegistrationAction, IngressAction,
    IngressDecision, IngressDecisionInput, IngressReason, IntermediateLinkRequestAction,
    KeepAliveKind, LinkDestinationDataRoute, LinkLifecycleTransition, LinkRequestRoute,
    PathRequestAction, PathRequestDecisionInput, PathRequestExecutionIntent, PathRequestRoute,
    PathRequestStateObservation, ProofHandleFollowup, ProofLinkFollowup, SingleDataRoute,
    StagedPathRequestEgressDecision, STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD,
};
#[cfg(feature = "std")]
#[allow(unused_imports)]
pub use crate::transport_engine::{decide_link_handle_followup, LinkHandleFollowup};

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
        LinkStatus::Stale
            if !restart_outlinks && elapsed > output_stale_after + output_close_after =>
        {
            OutLinkMaintenanceAction::TeardownAndRemove
        }
        LinkStatus::Pending if elapsed > output_repeat_after => {
            OutLinkMaintenanceAction::RepeatRequest
        }
        LinkStatus::Closed => OutLinkMaintenanceAction::CloseAndRemove,
        _ => OutLinkMaintenanceAction::NoOp,
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
        allow_duplicate_packet, build_path_request_decision_input, classify_keepalive_byte,
        classify_link_data, decide_announce_discovery_route, decide_announce_retransmit_action,
        decide_duplicate_outcome, decide_fixed_destination_route,
        decide_in_link_maintenance_action, decide_in_link_registration_action, decide_ingress,
        decide_ingress_from_duplicate_outcome, decide_ingress_from_input,
        decide_ingress_with_duplicate_policy, decide_intermediate_link_request_action,
        decide_link_destination_data_route, decide_link_handle_followup,
        decide_link_lifecycle_transition, decide_link_request_route,
        decide_old_announce_retransmit, decide_out_link_maintenance_action,
        decide_path_request_action, decide_path_request_action_from_input,
        decide_path_request_action_from_state, decide_path_request_execution_intent,
        decide_path_request_route, decide_proof_handle_followup, decide_proof_link_followup,
        decide_single_data_route, decide_staged_path_request_egress, duplicate_outcome,
        is_circular_path_request, is_in_link_pending_proof, is_path_request_packet,
        lookup_path_request_state, path_request_fixed_destination,
        recursive_broadcast_exclude_iface, should_consider_in_link_pending_proof,
        should_handle_fixed_destination_path_request, should_handle_keepalive_response,
        AnnounceDiscoveryRoute, AnnounceRetransmitAction, DuplicateOutcome, FixedDestinationRoute,
        InLinkMaintenanceAction, InLinkRegistrationAction, IngressAction, IngressDecision,
        IngressDecisionInput, IngressReason, IntermediateLinkRequestAction, KeepAliveKind,
        LinkDataAction, LinkDestinationDataRoute, LinkHandleFollowup, LinkLifecycleTransition,
        LinkRequestRoute, OutLinkMaintenanceAction, PathRequestAction, PathRequestDecisionInput,
        PathRequestExecutionIntent, PathRequestRoute, PathRequestStateObservation,
        ProofHandleFollowup, ProofLinkFollowup, SingleDataRoute, StagedPathRequestEgressDecision,
        STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD,
    };
    use crate::destination::link::LinkHandleResult;
    use crate::destination::link::LinkStatus;
    use crate::hash::AddressHash;
    use crate::packet::{Packet, PacketContext, PacketType};
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
    fn duplicate_decision_helper_matches_policy() {
        assert_eq!(
            decide_duplicate_outcome(PacketType::Data, PacketContext::None, false, true),
            DuplicateOutcome::AcceptNew
        );
        assert_eq!(
            decide_duplicate_outcome(PacketType::Announce, PacketContext::None, false, false),
            DuplicateOutcome::AcceptAllowedDuplicate
        );
        assert_eq!(
            decide_duplicate_outcome(PacketType::Data, PacketContext::None, false, false),
            DuplicateOutcome::DropDuplicate
        );
    }

    #[test]
    fn ingress_with_duplicate_policy_matches_composed_behavior() {
        let (dup, decision) = decide_ingress_with_duplicate_policy(
            PacketType::Data,
            PacketContext::None,
            false,
            false,
            false,
            true,
        );
        assert_eq!(dup, DuplicateOutcome::DropDuplicate);
        assert_eq!(
            decision,
            IngressDecision::DropDuplicate(IngressReason::DuplicateFiltered)
        );
    }

    #[test]
    fn ingress_from_known_duplicate_outcome() {
        let decision = decide_ingress_from_duplicate_outcome(
            PacketType::Data,
            false,
            DuplicateOutcome::AcceptAllowedDuplicate,
            true,
        );
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
    fn ingress_from_input_mapping() {
        let decision = decide_ingress_from_input(IngressDecisionInput {
            packet_type: PacketType::Data,
            fixed_destination_handled: false,
            duplicate: DuplicateOutcome::DropDuplicate,
            broadcast_enabled: true,
        });
        assert_eq!(
            decision,
            IngressDecision::DropDuplicate(IngressReason::DuplicateFiltered)
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
    fn path_request_execution_intent_mapping() {
        assert_eq!(
            decide_path_request_execution_intent(true, true, Some(3), false),
            PathRequestExecutionIntent::LocalDestinationResponse
        );
        assert_eq!(
            decide_path_request_execution_intent(false, true, Some(3), false),
            PathRequestExecutionIntent::ScheduleRemoteResponse { hops: 3 }
        );
        assert_eq!(
            decide_path_request_execution_intent(false, true, Some(3), true),
            PathRequestExecutionIntent::DropCircular
        );
        assert_eq!(
            decide_path_request_execution_intent(false, false, None, false),
            PathRequestExecutionIntent::RecursiveBroadcast
        );
    }

    #[test]
    fn path_request_action_mapping() {
        let destination = AddressHash::new([5u8; 16]);
        let iface = AddressHash::new([6u8; 16]);
        assert_eq!(
            decide_path_request_action(destination, iface, true, true, Some(2), false),
            PathRequestAction::LocalDestinationResponse {
                ingress_iface: iface
            }
        );
        assert_eq!(
            decide_path_request_action(destination, iface, false, true, Some(4), false),
            PathRequestAction::ScheduleRemoteResponse {
                destination,
                ingress_iface: iface,
                hops: 4
            }
        );
    }

    #[test]
    fn path_request_action_from_state_mapping() {
        let destination = AddressHash::new([8u8; 16]);
        let iface = AddressHash::new([9u8; 16]);
        let requestor = AddressHash::new([10u8; 16]);
        let received_from = AddressHash::new([11u8; 16]);
        assert_eq!(
            decide_path_request_action_from_state(
                destination,
                iface,
                Some(&requestor),
                Some(&received_from),
                false,
                true,
                Some(2),
            ),
            PathRequestAction::ScheduleRemoteResponse {
                destination,
                ingress_iface: iface,
                hops: 2
            }
        );
        assert_eq!(
            decide_path_request_action_from_state(
                destination,
                iface,
                Some(&requestor),
                Some(&requestor),
                false,
                true,
                Some(2),
            ),
            PathRequestAction::DropCircular { destination }
        );
    }

    #[test]
    fn path_request_action_from_input_mapping() {
        let destination = AddressHash::new([12u8; 16]);
        let iface = AddressHash::new([13u8; 16]);
        let input = PathRequestDecisionInput {
            request_destination: destination,
            ingress_iface: iface,
            requesting_transport: None,
            entry_received_from: None,
            has_local_destination: false,
            retransmit_enabled: false,
            known_hops: None,
        };
        assert_eq!(
            decide_path_request_action_from_input(input),
            PathRequestAction::RecursiveBroadcast {
                destination,
                exclude_iface: iface
            }
        );
    }

    #[test]
    fn path_request_state_lookup_mapping() {
        let destination = AddressHash::new([7u8; 16]);
        let other = AddressHash::new([8u8; 16]);
        let recv = AddressHash::new([9u8; 16]);
        let observation = lookup_path_request_state(
            destination,
            &[(other, AddressHash::new([1u8; 16])), (destination, recv)],
            &[(other, 2), (destination, 4)],
        );
        assert_eq!(
            observation,
            PathRequestStateObservation {
                entry_received_from: Some(recv),
                known_hops: Some(4),
            }
        );
    }

    #[test]
    fn path_request_decision_input_builder_mapping() {
        let destination = AddressHash::new([1u8; 16]);
        let iface = AddressHash::new([2u8; 16]);
        let observation = PathRequestStateObservation {
            entry_received_from: Some(AddressHash::new([3u8; 16])),
            known_hops: Some(5),
        };
        let input = build_path_request_decision_input(
            destination,
            iface,
            Some(AddressHash::new([4u8; 16])),
            true,
            false,
            observation,
        );
        assert_eq!(input.request_destination, destination);
        assert_eq!(input.ingress_iface, iface);
        assert_eq!(
            input.requesting_transport,
            Some(AddressHash::new([4u8; 16]))
        );
        assert_eq!(input.entry_received_from, observation.entry_received_from);
        assert_eq!(input.has_local_destination, true);
        assert_eq!(input.retransmit_enabled, false);
        assert_eq!(input.known_hops, observation.known_hops);
    }

    #[test]
    fn link_lifecycle_transition_mapping() {
        assert_eq!(
            decide_link_lifecycle_transition(IngressAction::LinkRequest, true, false, false),
            LinkLifecycleTransition::AddPending
        );
        assert_eq!(
            decide_link_lifecycle_transition(IngressAction::LinkRequest, true, true, true),
            LinkLifecycleTransition::None
        );
        assert_eq!(
            decide_link_lifecycle_transition(IngressAction::Proof, false, false, true),
            LinkLifecycleTransition::Activate
        );
        assert_eq!(
            decide_link_lifecycle_transition(IngressAction::Proof, false, false, false),
            LinkLifecycleTransition::None
        );
    }

    #[test]
    fn recursive_broadcast_iface_extraction() {
        let destination = AddressHash::new([1u8; 16]);
        let iface = AddressHash::new([2u8; 16]);
        assert_eq!(
            recursive_broadcast_exclude_iface(PathRequestAction::RecursiveBroadcast {
                destination,
                exclude_iface: iface
            }),
            Some(iface)
        );
        assert_eq!(
            recursive_broadcast_exclude_iface(PathRequestAction::DropCircular { destination }),
            None
        );
    }

    #[test]
    fn staged_path_request_egress_mapping() {
        let destination = AddressHash::new([1u8; 16]);
        let iface = AddressHash::new([2u8; 16]);

        assert!(matches!(
            decide_staged_path_request_egress(
                PathRequestAction::RecursiveBroadcast {
                    destination,
                    exclude_iface: iface,
                },
                false
            ),
            StagedPathRequestEgressDecision::EmitRecursive { exclude_iface } if exclude_iface == iface
        ));
        assert!(matches!(
            decide_staged_path_request_egress(
                PathRequestAction::ScheduleRemoteResponse {
                    destination,
                    ingress_iface: iface,
                    hops: 1,
                },
                true
            ),
            StagedPathRequestEgressDecision::CountOnly
        ));
        assert!(matches!(
            decide_staged_path_request_egress(
                PathRequestAction::ScheduleRemoteResponse {
                    destination,
                    ingress_iface: iface,
                    hops: 1,
                },
                false
            ),
            StagedPathRequestEgressDecision::None
        ));
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
        assert_eq!(decide_proof_link_followup(true), ProofLinkFollowup::SendRtt);
        assert_eq!(decide_proof_link_followup(false), ProofLinkFollowup::NoOp);
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
    fn in_link_pending_proof_gate_combines_candidate_and_state() {
        assert!(is_in_link_pending_proof(
            PacketType::Proof,
            PacketContext::LinkRequestProof,
            true
        ));
        assert!(!is_in_link_pending_proof(
            PacketType::Proof,
            PacketContext::LinkRequestProof,
            false
        ));
        assert!(!is_in_link_pending_proof(
            PacketType::Data,
            PacketContext::LinkRequestProof,
            true
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

    #[test]
    fn path_request_packet_classification() {
        assert!(is_path_request_packet(
            PacketType::Data,
            PacketContext::Request,
            b"anything"
        ));
        assert!(is_path_request_packet(
            PacketType::Data,
            PacketContext::None,
            STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD
        ));
        assert!(!is_path_request_packet(
            PacketType::Announce,
            PacketContext::Request,
            STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD
        ));
    }

    #[test]
    fn path_request_fixed_destination_is_stable() {
        let a = path_request_fixed_destination();
        let b = path_request_fixed_destination();
        assert_eq!(a, b);
        assert_ne!(a, AddressHash::new_empty());
    }

    #[test]
    fn fixed_destination_path_request_gate() {
        let fixed = path_request_fixed_destination();
        assert!(should_handle_fixed_destination_path_request(
            &fixed,
            &fixed,
            PacketType::Data,
            PacketContext::Request,
            b"anything"
        ));
        assert!(!should_handle_fixed_destination_path_request(
            &fixed,
            &fixed,
            PacketType::Announce,
            PacketContext::Request,
            b"anything"
        ));
        let other = AddressHash::new([9u8; 16]);
        assert!(!should_handle_fixed_destination_path_request(
            &other,
            &fixed,
            PacketType::Data,
            PacketContext::Request,
            b"anything"
        ));
    }
}
