//! Routing table for destination paths.
//!
//! This module provides the PathTable which stores and manages
//! paths to remote destinations. It handles:
//!
//! - Storing routes to known destinations
//! - Processing announcements to update routes
//! - Forwarding packets to the next hop
//! - Path lookup and refresh
//!
//! # Overview
//!
//! When a destination announces itself on the network, the announcement
//! is processed and a path entry is created in the PathTable. This
//! allows the Transport to know which interface to forward packets to
//! to reach that destination.
//!
//! # Usage
//!
//! This is used internally by the Transport to manage routing state.

use std::collections::HashMap;

use crate::async_backend::time::Instant;
use crate::{
    hash::{AddressHash, Hash},
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType},
};

/// An entry in the path table representing a known route to a destination.
pub struct PathEntry {
    /// When this path was last updated.
    pub timestamp: Instant,
    /// The next hop towards the destination.
    pub received_from: AddressHash,
    /// The hop count to reach the destination.
    pub hops: u8,
    /// The interface to use for this path.
    pub iface: AddressHash,
    /// Hash of the announcement packet that created this entry.
    pub packet_hash: Hash,
}

/// Table for managing routes to destinations.
///
/// PathTable stores the known paths to remote destinations discovered
/// through announcements. It is used by the Transport to determine
/// where to forward packets.
pub struct PathTable {
    /// Map of destination addresses to path entries.
    map: HashMap<AddressHash, PathEntry>,
    /// Whether to prefer newer routes with the same hop count.
    reroute_eager: bool,
}

impl PathTable {
    /// Creates a new PathTable.
    ///
    /// # Arguments
    ///
    /// * `reroute_eager` - If true, prefer newer routes with same hop count
    pub fn new(reroute_eager: bool) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
        }
    }

    /// Gets a path entry for a destination.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination address to look up
    ///
    /// # Returns
    ///
    /// The path entry if found
    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    /// Gets both the next hop and interface for a destination.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination address to look up
    ///
    /// # Returns
    ///
    /// Tuple of (next_hop, interface) if found
    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface))
    }

    /// Gets the interface for a destination.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination address to look up
    ///
    /// # Returns
    ///
    /// The interface address if found
    pub fn next_hop_iface(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.iface)
    }

    /// Gets the next hop for a destination.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination address to look up
    ///
    /// # Returns
    ///
    /// The next hop address if found
    pub fn next_hop(&self, destination: &AddressHash) -> Option<AddressHash> {
        self.map.get(destination).map(|entry| entry.received_from)
    }

    /// Handles an announcement packet and updates the path table.
    ///
    /// If the announcement provides a better route (fewer hops or
    /// newer with same hops), the path entry is updated.
    ///
    /// # Arguments
    ///
    /// * `announce` - The announcement packet
    /// * `transport_id` - Optional transport ID of the sender
    /// * `iface` - The interface the announcement was received on
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) {
        let hops = announce.header.hops + 1;

        // Check if we should update the existing route
        if let Some(existing_entry) = self.map.get(&announce.destination) {
            // Only update if we have a shorter path
            if hops > existing_entry.hops {
                return;
            }
            // If not eager rerouting, don't update equal hop paths
            if !self.reroute_eager && hops == existing_entry.hops {
                return;
            }
        }

        // Determine the next hop - either the transport ID or the announcing destination
        let received_from = transport_id.unwrap_or(announce.destination);

        // Create new path entry
        let new_entry = PathEntry {
            timestamp: Instant::now(),
            received_from,
            hops,
            iface,
            packet_hash: announce.hash(),
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );
    }

    /// Handles an inbound packet, setting up transport routing.
    ///
    /// Converts a Type1 packet to Type2 with the next hop information.
    ///
    /// # Arguments
    ///
    /// * `original_packet` - The packet to handle
    /// * `lookup` - Optional specific destination to look up
    ///
    /// # Returns
    ///
    /// Tuple of (modified packet, interface to send on)
    pub fn handle_inbound_packet(
        &self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        // Use provided lookup or fall back to packet's destination
        let lookup = lookup.unwrap_or(original_packet.destination);

        // Find the path entry
        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        // Return modified packet with transport header and interface
        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Authenticated,
                    header_type: HeaderType::Type2,
                    propagation_type: original_packet.header.propagation_type,
                    destination_type: original_packet.header.destination_type,
                    packet_type: original_packet.header.packet_type,
                    hops: original_packet.header.hops + 1,
                },
                ifac: None,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }

    /// Refreshes the timestamp for a destination.
    ///
    /// # Arguments
    ///
    /// * `destination` - The destination to refresh
    pub fn refresh(&mut self, destination: &AddressHash) {
        if let Some(entry) = self.map.get_mut(destination) {
            entry.timestamp = Instant::now();
        }
    }

    /// Handles an outbound packet, determining the next hop.
    ///
    /// Looks up the destination in the path table and sets up
    /// transport routing if a path is known.
    ///
    /// # Arguments
    ///
    /// * `original_packet` - The packet to handle
    ///
    /// # Returns
    ///
    /// Tuple of (modified packet, interface to send on)
    pub fn handle_packet(&mut self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        // Type2 packets already have transport headers - don't modify
        if original_packet.header.header_type == HeaderType::Type2 {
            return (*original_packet, None);
        }

        // Announcements are handled separately
        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        // Plain and Group destinations don't use transport routing
        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        // Look up the path
        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        // Return packet with transport header
        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Authenticated,
                    header_type: HeaderType::Type2,
                    propagation_type: original_packet.header.propagation_type,
                    destination_type: original_packet.header.destination_type,
                    packet_type: original_packet.header.packet_type,
                    hops: original_packet.header.hops,
                },
                ifac: original_packet.ifac,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }
}
