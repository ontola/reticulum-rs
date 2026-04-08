//! Message types shared between the interface layer and transport.
//!
//! These types do not depend on Tokio or Embassy; they can be used on any target that has
//! [`crate::hash`] and [`crate::packet`] (typically with the `alloc` feature).

use crate::hash::AddressHash;
use crate::packet::Packet;

/// How a packet should be sent on the interface side (broadcast vs direct).
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    /// Broadcast to all interfaces, optionally excluding one.
    Broadcast(Option<AddressHash>),
    /// Send only to the interface with this address.
    Direct(AddressHash),
}

/// Command to transmit a packet through an interface.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Packet,
}

/// A packet received from an interface, tagged with which interface saw it.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RxMessage {
    pub address: AddressHash,
    pub packet: Packet,
}
