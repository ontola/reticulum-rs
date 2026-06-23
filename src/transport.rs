use crate::async_backend::time;
use crate::async_backend::CancellationToken;
use alloc::sync::Arc;
use announce_limits::AnnounceLimits;
use announce_table::AnnounceTable;
use core::future::Future;
use link_table::LinkTable;
use packet_cache::PacketCache;
use path_requests::PathRequests;
use path_requests::TagBytes;
use path_table::PathTable;
use rand_core::OsRng;
use std::collections::HashMap;
use std::time::Duration;

use crate::async_backend::broadcast;
use crate::async_backend::Mutex;
use crate::async_backend::MutexGuard;

use crate::destination::link::Link;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkHandleResult;
use crate::destination::link::LinkId;
use crate::destination::link::LinkStatus;
use crate::destination::DestinationAnnounce;
use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::destination::SingleOutputDestination;

use crate::error::RnsError;

use crate::hash::AddressHash;
use crate::hash::Hash;
use crate::identity::PrivateIdentity;

use crate::iface::InterfaceManager;
use crate::iface::InterfaceRxReceiver;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;

use crate::async_select;

use crate::packet::DestinationType;
use crate::packet::Packet;
use crate::packet::PacketDataBuffer;

use crate::transport_engine::{
    build_path_request_decision_input, decide_announce_discovery_route,
    decide_announce_retransmit_action, decide_duplicate_outcome, decide_ingress_from_input,
    decide_link_destination_data_route, decide_link_handle_followup,
    decide_link_lifecycle_transition, decide_link_request_route, decide_old_announce_retransmit,
    decide_path_request_action_from_input, decide_proof_handle_followup, decide_single_data_route,
    is_in_link_pending_proof, path_request_fixed_destination,
    should_consider_in_link_pending_proof, should_handle_fixed_destination_path_request,
    should_handle_keepalive_response, AnnounceDiscoveryRoute, AnnounceRetransmitAction,
    DuplicateOutcome, IngressAction, IngressDecision, IngressDecisionInput, IngressReason,
    LinkDestinationDataRoute, LinkHandleFollowup, LinkLifecycleTransition, LinkRequestRoute,
    PathRequestAction, PathRequestStateObservation, ProofHandleFollowup, SingleDataRoute,
};
use engine::{
    decide_in_link_maintenance_action, decide_intermediate_link_request_action,
    decide_out_link_maintenance_action, InLinkMaintenanceAction, IntermediateLinkRequestAction,
    OutLinkMaintenanceAction,
};

mod announce_limits;
mod announce_table;
pub(crate) mod engine;
mod link_table;
mod packet_cache;
mod path_requests;
mod path_table;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

/// Tokio-backed task adapter used by the std transport.
#[derive(Clone)]
pub struct TokioRuntime;

impl TokioRuntime {
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        crate::async_backend::spawn(fut);
    }
}

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    pub link_check: Duration,
    pub in_link_stale: Duration,
    pub in_link_close: Duration,
    pub out_link_restart: Duration,
    pub out_link_stale: Duration,
    pub out_link_close: Duration,
    pub out_link_repeat: Duration,
    pub out_link_keep: Duration,
    pub iface_cleanup: Duration,
    pub announces_retransmit: Duration,
    pub old_announces_retransmit: Duration,
    pub keep_packet_cached: Duration,
    pub packet_cache_cleanup: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            link_check: Duration::from_secs(1),
            in_link_stale: Duration::from_secs(10),
            in_link_close: Duration::from_secs(5),
            out_link_restart: Duration::from_secs(60),
            out_link_stale: Duration::from_secs(10),
            out_link_close: Duration::from_secs(5),
            out_link_repeat: Duration::from_secs(6),
            out_link_keep: Duration::from_secs(5),
            iface_cleanup: Duration::from_secs(10),
            announces_retransmit: Duration::from_secs(1),
            old_announces_retransmit: Duration::from_secs(60),
            keep_packet_cached: Duration::from_secs(180),
            packet_cache_cleanup: Duration::from_secs(90),
        }
    }
}

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,

    /// If `false`, `Transport` will replace known routes to distant destinations
    /// only if they are shorter (fewer hops) than the new one.
    /// If `true`, routes will also be replaced if the new route is equally long.
    /// So newer routes are preferred over older ones.
    reroute_eager: bool,

    /// Attempt to reopen lost links once they have been closed.
    restart_outlinks: bool,

    /// Resend announces of remote destinations at a slower pace once
    /// the initial round of announces is over.
    announce_forever: bool,

    timer_config: TimerConfig,

    /// The runtime used for spawning tasks and sleeping.
    /// Defaults to TokioRuntime if not specified.
    pub runtime: TokioRuntime,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
    pub hops: u8,
}

pub(crate) struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,

    path_table: PathTable,
    announce_table: AnnounceTable,
    link_table: LinkTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,

    announce_limits: AnnounceLimits,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,

    packet_cache: Mutex<PacketCache>,

    path_requests: PathRequests,

    link_in_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    received_data_tx: broadcast::Sender<ReceivedData>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, broadcast: bool) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            timer_config: TimerConfig::default(),
            runtime: TokioRuntime,
        }
    }

    /// Creates a new TransportConfig with a custom runtime.
    pub fn new_with_runtime<T: Into<String>>(
        name: T,
        identity: &PrivateIdentity,
        broadcast: bool,
        runtime: TokioRuntime,
    ) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            timer_config: TimerConfig::default(),
            runtime,
        }
    }

    pub fn set_retransmit(mut self, retransmit: bool) -> Self {
        self.retransmit = retransmit;
        self
    }

    pub fn set_broadcast(mut self, broadcast: bool) -> Self {
        self.broadcast = broadcast;
        self
    }

    pub fn set_reroute_eager(mut self, reroute_eager: bool) -> Self {
        self.reroute_eager = reroute_eager;
        self
    }

    pub fn set_restart_outlinks(mut self, restart_outlinks: bool) -> Self {
        self.restart_outlinks = restart_outlinks;
        self
    }

    pub fn set_announce_forever(mut self, announce_forever: bool) -> Self {
        self.announce_forever = announce_forever;
        self
    }

    pub fn set_timer_config(mut self, timer_config: TimerConfig) -> Self {
        self.timer_config = timer_config;
        self
    }

    pub fn set_runtime(mut self, runtime: TokioRuntime) -> Self {
        self.runtime = runtime;
        self
    }

    pub fn build(self) -> Transport {
        Transport::new(self)
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            timer_config: Default::default(),
            runtime: TokioRuntime,
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let (announce_tx, _) = broadcast::channel(16);
        let (link_in_event_tx, _) = broadcast::channel(16);
        let (link_out_event_tx, _) = broadcast::channel(16);
        let (received_data_tx, _) = broadcast::channel(16);
        let (iface_messages_tx, _) = broadcast::channel(16);

        let iface_manager = InterfaceManager::new(16);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let transport_id = if config.retransmit {
            Some(*config.identity.address_hash())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = path_request_fixed_destination();

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
        let runtime = config.runtime.clone();
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(reroute_eager),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            path_requests,
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone(),
            received_data_tx: received_data_tx.clone(),
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
        }));

        {
            let handler = handler.clone();
            runtime.spawn(manage_transport(
                handler,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        Self {
            name,
            iface_manager,
            link_in_event_tx,
            link_out_event_tx,
            received_data_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self.handler.lock().await.path_table.handle_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet).await;
            log::trace!("Sent outbound packet to {}", iface);
        }

        // TODO handle other cases
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.handler
            .lock()
            .await
            .send_packet(
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    link.touch();
                    sent_packets.push(packet.hash());
                }
            }
        }

        if sent_packets.is_empty() {
            log::trace!(
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }

        sent_packets
    }

    pub async fn send_to_in_links(&self, destination: &AddressHash, payload: &[u8]) {
        let handler = self.handler.lock().await;
        let mut count = 0usize;
        for link in handler.in_links.values() {
            let mut link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    link.touch();
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no input links for {} destination",
                self.name,
                destination
            );
        }
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.out_links.get(link_id).cloned()
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.in_links.get(link_id).cloned()
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let link = self
            .handler
            .lock()
            .await
            .out_links
            .get(&destination.address_hash)
            .cloned();

        if let Some(link) = link {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = Link::new(destination, self.link_out_event_tx.clone());

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        link
    }

    pub async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        let link = if let Some(link) = self.find_in_link(&link_id).await {
            Some(link)
        } else {
            self.find_out_link(&link_id).await
        };
        if let Some(link) = link {
            let mut link = link.lock().await;
            if let Some(packet) = link.teardown()? {
                drop(link);
                self.send_packet(packet).await
            }
        } else {
            log::warn!("tp({}): close link {link_id} not found", self.name)
        }
        Ok(())
    }

    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        self.handler
            .lock()
            .await
            .request_path(destination, on_iface, tag)
            .await
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.subscribe()
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &mut self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    pub async fn get_in_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler
            .lock()
            .await
            .single_in_destinations
            .get(address)
            .cloned()
    }

    pub async fn get_out_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleOutputDestination>>> {
        self.handler
            .lock()
            .await
            .single_out_destinations
            .get(address)
            .cloned()
    }

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.has_destination(address)
    }

    pub async fn knows_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.knows_destination(address)
    }

    #[cfg(test)]
    pub(crate) fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        // Direct access to handler for in-crate unit tests.
        self.handler.clone()
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    async fn send_packet(&self, packet: Packet) {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet,
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    async fn filter_duplicate_packets(&self, packet: &Packet) -> DuplicateOutcome {
        let should_consider =
            should_consider_in_link_pending_proof(packet.header.packet_type, packet.context);

        let destination_pending = if should_consider {
            if let Some(link) = self.in_links.get(&packet.destination) {
                link.lock().await.status().not_yet_active()
            } else {
                false
            }
        } else {
            false
        };
        let in_link_pending_proof = is_in_link_pending_proof(
            packet.header.packet_type,
            packet.context,
            destination_pending,
        );

        let is_new = self.packet_cache.lock().await.update(packet);

        decide_duplicate_outcome(
            packet.header.packet_type,
            packet.context,
            in_link_pending_proof,
            is_new,
        )
    }

    async fn request_path(
        &mut self,
        address: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        let packet = self.path_requests.generate(address, tag);

        self.send(TxMessage {
            tx_type: TxMessageType::Broadcast(on_iface),
            packet,
        })
        .await;
    }
}

async fn handle_proof<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        let activated = matches!(
            link.handle_packet(packet, true),
            LinkHandleResult::Activated
        );
        match decide_link_lifecycle_transition(IngressAction::Proof, false, false, activated) {
            LinkLifecycleTransition::Activate => {
                let rtt_packet = link.create_rtt();
                handler.send_packet(rtt_packet).await;
            }
            LinkLifecycleTransition::AddPending | LinkLifecycleTransition::None => {}
        }
    }

    let maybe_packet = handler.link_table.handle_proof(packet);
    match decide_proof_handle_followup(maybe_packet) {
        ProofHandleFollowup::SendDirect { packet, iface } => {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet,
                })
                .await;
        }
        ProofHandleFollowup::NoOp => {}
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
    lookup: Option<AddressHash>,
) -> bool {
    let (packet, maybe_iface) = handler.path_table.handle_inbound_packet(packet, lookup);

    if let Some(iface) = maybe_iface {
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;
    }

    maybe_iface.is_some()
}

async fn handle_keepalive_response<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
) -> bool {
    let first_byte = packet.data.as_slice().first().copied();
    if should_handle_keepalive_response(packet.context, first_byte) {
        let lookup = handler.link_table.handle_keepalive(packet);

        if let Some((propagated, iface)) = lookup {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: propagated,
                })
                .await;
        }

        return true;
    }

    false
}

async fn handle_data<'a>(packet: &Packet, handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

    if packet.header.destination_type == DestinationType::Link {
        let lookup = handler.link_table.original_destination(&packet.destination);
        let route = decide_link_destination_data_route(lookup.is_some());

        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet, false);
            match decide_link_handle_followup(result) {
                LinkHandleFollowup::SendKeepAliveResponse => {
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_packet(packet).await;
                }
                LinkHandleFollowup::SendProof(proof) => {
                    handler.send_packet(proof).await;
                }
                LinkHandleFollowup::NoOp => {}
            };
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let _ = link.handle_packet(packet, true);
            data_handled = true;
        }

        if handle_keepalive_response(packet, &handler).await {
            return;
        }

        if route == LinkDestinationDataRoute::ProcessLocalAndForward {
            let sent = send_to_next_hop(packet, &handler, lookup).await;

            log::trace!(
                "tp({}): {} packet to remote link {}",
                handler.config.name,
                if sent {
                    "forwarded"
                } else {
                    "could not forward"
                },
                packet.destination
            );
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        let has_local_destination = handler
            .single_in_destinations
            .contains_key(&packet.destination);

        match decide_single_data_route(has_local_destination) {
            SingleDataRoute::DeliverLocal => {
                data_handled = true;
                handler
                    .received_data_tx
                    .send(ReceivedData {
                        destination: packet.destination,
                        data: packet.data,
                    })
                    .ok();
            }
            SingleDataRoute::Forward => {
                data_handled = send_to_next_hop(packet, &handler, None).await;
            }
        }
    }

    if data_handled {
        log::trace!(
            "tp({}): handle data request for {} dst={:2x} ctx={:2x}",
            handler.config.name,
            packet.destination,
            packet.header.destination_type as u8,
            packet.context as u8,
        );
    }
}

async fn handle_announce<'a>(
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if handler.has_destination(&packet.destination) {
        return;
    }

    if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
        log::info!(
            "tp({}): too many announces from {}, blocked for {} seconds",
            handler.config.name,
            &packet.destination,
            blocked_until.as_secs(),
        );
        return;
    }

    let destination_known = handler.has_destination(&packet.destination);

    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
        let dest_hash = destination.identity.address_hash;
        let destination = Arc::new(Mutex::new(destination));
        let has_single_out_destination = handler
            .single_out_destinations
            .contains_key(&packet.destination);
        match decide_announce_discovery_route(destination_known, has_single_out_destination) {
            AnnounceDiscoveryRoute::RegisterAndTrackPath => {
                log::trace!(
                    "tp({}): new announce for {}",
                    handler.config.name,
                    packet.destination
                );

                handler
                    .single_out_destinations
                    .insert(packet.destination, destination.clone());
                handler.announce_table.add(packet, dest_hash, iface);
                handler
                    .path_table
                    .handle_announce(packet, packet.transport, iface);
            }
            AnnounceDiscoveryRoute::TrackPathOnly => {
                handler.announce_table.add(packet, dest_hash, iface);
                handler
                    .path_table
                    .handle_announce(packet, packet.transport, iface);
            }
            AnnounceDiscoveryRoute::IgnoreKnownDestination => {}
        }

        let transport_id = *handler.config.identity.address_hash();
        let maybe_message = if handler.config.retransmit {
            handler.announce_table.new_packet(&dest_hash, &transport_id)
        } else {
            None
        };

        match decide_announce_retransmit_action(handler.config.retransmit, maybe_message.is_some())
        {
            AnnounceRetransmitAction::SendGeneratedPacket => {
                if let Some(message) = maybe_message {
                    handler.send(message).await;
                }
            }
            AnnounceRetransmitAction::Skip => {}
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(app_data),
            hops: packet.header.hops,
        });
    }
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if let Some(request) = handler.path_requests.decode(packet.data.as_slice()) {
        let maybe_local_dest = handler
            .single_in_destinations
            .get(&request.destination)
            .cloned();
        let maybe_entry = handler.path_table.get(&request.destination);
        let maybe_known_hops = maybe_entry.map(|entry| entry.hops);

        let input = build_path_request_decision_input(
            request.destination,
            iface,
            request.requesting_transport,
            maybe_local_dest.is_some(),
            handler.config.retransmit,
            PathRequestStateObservation {
                entry_received_from: maybe_entry.map(|entry| entry.received_from),
                known_hops: maybe_known_hops,
            },
        );
        match decide_path_request_action_from_input(input) {
            PathRequestAction::LocalDestinationResponse { ingress_iface } => {
                if let Some(dest) = maybe_local_dest {
                    let response = dest
                        .lock()
                        .await
                        .path_response(OsRng, None)
                        .expect("valid path response");

                    handler
                        .send(TxMessage {
                            tx_type: TxMessageType::Direct(ingress_iface),
                            packet: response,
                        })
                        .await;

                    log::trace!(
                        "tp({}): send direct path response over {}",
                        handler.config.name,
                        ingress_iface
                    );
                }
            }
            PathRequestAction::ScheduleRemoteResponse {
                destination,
                ingress_iface,
                hops,
            } => {
                handler
                    .announce_table
                    .add_response(destination, ingress_iface, hops);

                log::trace!(
                    "tp({}): scheduled remote path response to {} ({} hops) over {}",
                    handler.config.name,
                    destination,
                    hops,
                    ingress_iface
                );
            }
            PathRequestAction::DropCircular { destination } => {
                log::trace!(
                    "tp({}): dropping circular path request from {}",
                    handler.config.name,
                    destination
                );
            }
            PathRequestAction::RecursiveBroadcast {
                destination,
                exclude_iface,
            } => {
                if let Some(packet) = handler.path_requests.generate_recursive(
                    &destination,
                    Some(exclude_iface),
                    None,
                ) {
                    handler
                        .send(TxMessage {
                            tx_type: TxMessageType::Broadcast(Some(exclude_iface)),
                            packet,
                        })
                        .await;
                }
            }
        }
    }
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) -> bool {
    if should_handle_fixed_destination_path_request(
        &packet.destination,
        &handler.fixed_dest_path_requests,
        packet.header.packet_type,
        packet.context,
        packet.data.as_slice(),
    ) {
        handle_path_request(packet, handler, iface).await;
        true
    } else {
        false
    }
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut destination = destination.lock().await;
    let destination_requested_link_proof = matches!(
        destination.handle_packet(packet),
        DestinationHandleStatus::LinkProof
    );
    let link_id = LinkId::from(packet);
    let in_link_already_exists = handler.in_links.contains_key(&link_id);

    match decide_link_lifecycle_transition(
        IngressAction::LinkRequest,
        destination_requested_link_proof,
        in_link_already_exists,
        in_link_already_exists,
    ) {
        LinkLifecycleTransition::AddPending => {
            log::trace!(
                "tp({}): send proof to {}",
                handler.config.name,
                packet.destination
            );

            let link = Link::new_from_request(
                packet,
                destination.sign_key().clone(),
                destination.desc,
                handler.link_in_event_tx.clone(),
            );

            if let Ok(mut link) = link {
                handler.send_packet(link.prove()).await;

                log::debug!(
                    "tp({}): save input link {} for destination {}",
                    handler.config.name,
                    link.id(),
                    link.destination().address_hash
                );

                handler
                    .in_links
                    .insert(*link.id(), Arc::new(Mutex::new(link)));
            }
        }
        LinkLifecycleTransition::Activate | LinkLifecycleTransition::None => {}
    }
}

async fn handle_link_request_as_intermediate<'a>(
    received_from: AddressHash,
    next_hop: AddressHash,
    next_hop_iface: AddressHash,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop,
        next_hop_iface,
    );

    send_to_next_hop(packet, &handler, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>,
) {
    let maybe_local_destination = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned();
    let maybe_next_hop = handler.path_table.next_hop_full(&packet.destination);

    match decide_link_request_route(maybe_local_destination.is_some(), maybe_next_hop.is_some()) {
        LinkRequestRoute::LocalDestination => {
            log::trace!(
                "tp({}): handle link request for {}",
                handler.config.name,
                packet.destination
            );
            if let Some(destination) = maybe_local_destination {
                handle_link_request_as_destination(destination, packet, handler).await;
            }
        }
        LinkRequestRoute::Intermediate => {
            log::trace!(
                "tp({}): handle link request for remote destination {}",
                handler.config.name,
                packet.destination
            );
            match decide_intermediate_link_request_action(maybe_next_hop.is_some()) {
                IntermediateLinkRequestAction::AddLinkTableAndForward => {
                    if let Some((next_hop, next_iface)) = maybe_next_hop {
                        handle_link_request_as_intermediate(
                            iface, next_hop, next_iface, packet, handler,
                        )
                        .await;
                    }
                }
                IntermediateLinkRequestAction::Skip => {}
            }
        }
        LinkRequestRoute::DropUnknown => {
            log::trace!(
                "tp({}): dropping link request to unknown destination {}",
                handler.config.name,
                packet.destination
            );
        }
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let timer_config = handler.config.timer_config;
    let mut links_to_remove: Vec<AddressHash> = Vec::new();

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        match decide_in_link_maintenance_action(
            link.status(),
            link.elapsed(),
            timer_config.in_link_stale,
            timer_config.in_link_close,
        ) {
            InLinkMaintenanceAction::MarkStale => link.stale(),
            InLinkMaintenanceAction::TeardownAndRemove => {
                if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                    log::error!(
                        "tp({}): teardown stale in-link error: {err:?}",
                        handler.config.name
                    );
                    None
                }) {
                    handler.send_packet(packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            InLinkMaintenanceAction::NoOp => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(addr);
    }

    links_to_remove.clear();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        match decide_out_link_maintenance_action(
            link.status(),
            link.elapsed(),
            handler.config.restart_outlinks,
            timer_config.out_link_stale,
            timer_config.out_link_close,
            timer_config.out_link_restart,
            timer_config.out_link_repeat,
        ) {
            OutLinkMaintenanceAction::MarkStale => link.stale(),
            OutLinkMaintenanceAction::Restart => link.restart(),
            OutLinkMaintenanceAction::TeardownAndRemove => {
                if let Some(packet) = link.teardown().unwrap_or_else(|err| {
                    log::error!(
                        "tp({}): teardown stale out-link error: {err:?}",
                        handler.config.name
                    );
                    None
                }) {
                    handler.send_packet(packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            OutLinkMaintenanceAction::RepeatRequest => {
                log::warn!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
            }
            OutLinkMaintenanceAction::CloseAndRemove => {
                link.close();
                links_to_remove.push(*link_entry.0);
            }
            OutLinkMaintenanceAction::NoOp => {}
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(addr);
    }
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if link.status() == LinkStatus::Active {
            handler
                .send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST))
                .await;
        }
    }
}

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
}

async fn retransmit_announces<'a>(
    mut handler: MutexGuard<'a, TransportHandler>,
    retransmit_old: bool,
) {
    let transport_id = *handler.config.identity.address_hash();
    let messages = handler.announce_table.tx_to_retransmit(&transport_id);

    for message in messages {
        handler.send(message).await;
    }

    if retransmit_old {
        let messages = handler.announce_table.tx_to_retransmit_old(&transport_id);

        for message in messages {
            handler.send(message).await;
        }
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let timer_config = handler.lock().await.config.timer_config;
    let mut last_retransmit_old = if handler.lock().await.config.announce_forever {
        Some(time::Instant::now() - timer_config.old_announces_retransmit)
    } else {
        None
    };

    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        crate::async_backend::spawn(async move {
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        let _ = iface_messages_tx.send(message);

                        let packet = message.packet;

                        let mut handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        let fixed_destination_handled = handle_fixed_destinations(
                            &packet,
                            &mut handler,
                            message.address
                        ).await;

                        let duplicate_outcome = handler.filter_duplicate_packets(&packet).await;
                        let decision = decide_ingress_from_input(IngressDecisionInput {
                            packet_type: packet.header.packet_type,
                            fixed_destination_handled,
                            duplicate: duplicate_outcome,
                            broadcast_enabled: handler.config.broadcast,
                        });

                        match decision {
                            IngressDecision::HandleFixedDestination(reason) => {
                                log::trace!("tp({}): ingress skip: {:?}", handler.config.name, reason);
                                continue;
                            }
                            IngressDecision::DropDuplicate(reason) => {
                                log::debug!(
                                    "tp({}): dropping packet ({:?}): dst={}, ctx={:?}, type={:?}",
                                    handler.config.name,
                                    reason,
                                    packet.destination,
                                    packet.context,
                                    packet.header.packet_type
                                );
                                continue;
                            }
                            IngressDecision::Dispatch {
                                rebroadcast,
                                action,
                                reason,
                            } => {
                                if duplicate_outcome == DuplicateOutcome::AcceptAllowedDuplicate {
                                    log::trace!(
                                        "tp({}): accepted policy duplicate: dst={}, ctx={:?}, type={:?}",
                                        handler.config.name,
                                        packet.destination,
                                        packet.context,
                                        packet.header.packet_type
                                    );
                                }
                                if reason != IngressReason::FreshPacketDispatched {
                                    log::trace!(
                                        "tp({}): ingress dispatch reason: {:?}",
                                        handler.config.name,
                                        reason
                                    );
                                }
                                if rebroadcast {
                                    // TODO: remove separate handling for announces in handle_announce.
                                    // Send broadcast message except current iface address.
                                    handler
                                        .send(TxMessage {
                                            tx_type: TxMessageType::Broadcast(Some(message.address)),
                                            packet,
                                        })
                                        .await;
                                }

                                match action {
                                    IngressAction::Announce => {
                                        handle_announce(&packet, handler, message.address).await
                                    }
                                    IngressAction::LinkRequest => {
                                        handle_link_request(&packet, message.address, handler).await
                                    }
                                    IngressAction::Proof => handle_proof(&packet, handler).await,
                                    IngressAction::Data => handle_data(&packet, handler).await,
                                }
                            }
                        }
                    }
                };
            }
        })
    };

    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let link_check = timer_config.link_check;

        crate::async_backend::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(link_check) => {
                        handle_check_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let out_link_keep = timer_config.out_link_keep;

        crate::async_backend::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(out_link_keep) => {
                        handle_keep_links(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let iface_cleanup = timer_config.iface_cleanup;

        crate::async_backend::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(iface_cleanup) => {
                        handle_cleanup(handler.lock().await).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let packet_cache_cleanup = timer_config.packet_cache_cleanup;
        let keep_packet_cached = timer_config.keep_packet_cached;

        crate::async_backend::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(packet_cache_cleanup) => {
                        let mut handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(keep_packet_cached);

                        handler.link_table.remove_stale();
                    },
                }
            }
        });
    }

    if retransmit {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let announces_retransmit = timer_config.announces_retransmit;
        let old_announces_retransmit = timer_config.old_announces_retransmit;

        crate::async_backend::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                async_select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(announces_retransmit) => {
                        let mut retransmit_old = false;

                        if let Some(instant) = last_retransmit_old {
                            let now = time::Instant::now();
                            let elapsed = now - instant;
                            if decide_old_announce_retransmit(
                                elapsed,
                                old_announces_retransmit,
                            ) {
                                retransmit_old = true;
                                last_retransmit_old = Some(now);
                            }
                        }

                        retransmit_announces(handler.lock().await, retransmit_old).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::packet::{HeaderType, PacketType};

    #[tokio::test]
    async fn drop_duplicates() {
        let transport = Transport::new(TransportConfig::default().set_retransmit(true));
        let handler = transport.get_handler();

        let _source1 = AddressHash::new_from_slice(&[1u8; 32]);
        let _source2 = AddressHash::new_from_slice(&[2u8; 32]);
        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert_ne!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&announce)
                .await,
            DuplicateOutcome::DropDuplicate
        );

        handle_announce(&announce, handler.lock().await, next_hop_iface).await;

        let data_packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"foo"),
            destination,
            ..Default::default()
        };
        let duplicate: Packet = data_packet;

        let mut different_packet = data_packet;
        different_packet.data = PacketDataBuffer::new_from_slice(b"bar");

        assert_ne!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&data_packet)
                .await,
            DuplicateOutcome::DropDuplicate
        );
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
                == DuplicateOutcome::DropDuplicate
        );
        assert_ne!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&different_packet)
                .await,
            DuplicateOutcome::DropDuplicate
        );

        time::sleep(Duration::from_secs(2)).await;
        handler
            .lock()
            .await
            .packet_cache
            .lock()
            .await
            .release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert_ne!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await,
            DuplicateOutcome::DropDuplicate
        );
    }
}
