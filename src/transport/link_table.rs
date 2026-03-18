//! Table for tracking active links.
//!
//! This module provides the LinkTable which stores and manages
//! active links in the Reticulum network. It handles:
//!
//! - Storing link state and metadata
//! - Tracking link proofs and validation
//! - Propagating links back to requestors
//! - Cleaning up stale/unvalidated links
//!
//! # Overview
//!
//! When a link is established between two peers, an entry is added
//! to the LinkTable. This entry tracks the path through the network
//! and validates the link with proofs.
//!
//! # Usage
//!
//! This is used internally by the Transport to manage link state.

use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

/// An entry in the link table representing an active link.
pub struct LinkEntry {
    /// When this link was created.
    pub timestamp: Instant,
    /// When the link proof times out.
    pub proof_timeout: Instant,
    /// The next hop towards the destination.
    pub next_hop: AddressHash,
    /// The interface for the next hop.
    pub next_hop_iface: AddressHash,
    /// Where this link entry was received from.
    pub received_from: AddressHash,
    /// The original destination address.
    pub original_destination: AddressHash,
    /// Number of hops taken so far.
    pub taken_hops: u8,
    /// Remaining hops allowed.
    pub remaining_hops: u8,
    /// Whether this link has been validated with a proof.
    pub validated: bool,
}

/// Propagates a packet backwards towards the link requestor.
fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Authenticated,
            header_type: HeaderType::Type2,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop),
        context: packet.context,
        data: packet.data,
    };

    (propagated, entry.received_from)
}

/// Table for managing active links.
///
/// Stores link entries for established connections and handles
/// proof validation and propagation.
pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    /// Creates a new empty LinkTable.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Adds a new link entry to the table.
    ///
    /// # Arguments
    ///
    /// * `link_request` - The original link request packet
    /// * `destination` - The destination address
    /// * `received_from` - Where the request was received from
    /// * `next_hop` - The next hop towards the destination
    /// * `iface` - The interface for the next hop
    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
        iface: AddressHash,
    ) {
        let link_id = LinkId::from(link_request);

        // Don't overwrite existing link entries
        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();
        let taken_hops = link_request.header.hops + 1;

        let entry = LinkEntry {
            timestamp: now,
            proof_timeout: now + Duration::from_secs(600), // TODO: make configurable
            next_hop,
            next_hop_iface: iface,
            received_from,
            original_destination: destination,
            taken_hops,
            remaining_hops: 0,
            validated: false,
        };

        self.0.insert(link_id, entry);
    }

    /// Gets the original destination for a validated link.
    ///
    /// # Arguments
    ///
    /// * `link_id` - The link ID to look up
    ///
    /// # Returns
    ///
    /// The original destination if the link is validated
    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0
            .get(&link_id)
            .filter(|e| e.validated)
            .map(|e| e.original_destination)
    }

    /// Handles a keepalive packet for a link.
    ///
    /// # Arguments
    ///
    /// * `packet` - The keepalive packet
    ///
    /// # Returns
    ///
    /// The propagated packet and interface if found
    pub fn handle_keepalive(&self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        self.0
            .get(&packet.destination)
            .map(|entry| send_backwards(packet, entry))
    }

    /// Handles a proof packet for a link.
    ///
    /// Validates the link and propagates the proof back to the requestor.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof packet
    ///
    /// # Returns
    ///
    /// The propagated proof packet and interface if link exists
    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                Some(send_backwards(proof, entry))
            }
            None => None,
        }
    }

    /// Removes stale link entries.
    ///
    /// Removes entries that have timed out without receiving proof.
    /// Validated links are currently kept indefinitely (TODO).
    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                // TODO: remove active timed out links
            } else {
                // Remove unvalidated links that timed out
                if entry.proof_timeout <= now {
                    stale.push(link_id.clone());
                }
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}
