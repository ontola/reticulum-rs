//! Interface types for Reticulum networking.
//!
//! This module provides the interface abstraction for Reticulum, allowing
//! communication over various transport protocols like TCP, UDP, and more.
//!
//! # Overview
//!
//! Interfaces in Reticulum are the means by which packets are sent and received
//! over various networks. The interface system provides:
//!
//! - Async channel-based communication between interfaces and transport
//! - Interface management and spawning
//! - Support for multiple interface types (TCP, UDP, HDLC, etc.)
//!
//! # Interface Types
//!
//! - [`tcp_client::TcpClient`] - TCP client for connecting to peers
//! - [`tcp_server::TcpServer`] - TCP server for accepting connections
//! - [`udp::UdpInterface`] - UDP interface for datagram communication
//! - [`kaonic`] - Kaonic radio interface
//!
//! # Usage
//!
//! Interfaces are typically created and managed through the [`InterfaceManager`]:
//!
//! ```ignore
//! use reticulum::iface::{InterfaceManager, InterfaceContext};
//! use reticulum::iface::tcp_client::TcpClient;
//!
//! let mut manager = InterfaceManager::new(100);
//! let client_addr = manager.spawn(
//!     TcpClient::new("127.0.0.1:4242"),
//!     TcpClient::spawn
//! );
//! ```

pub mod hdlc;

pub mod kaonic;
pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use crate::async_backend::mpsc;
use crate::async_backend::spawn;
use crate::async_backend::Mutex;
use crate::async_backend::CancellationToken;
use crate::hash::AddressHash;
use crate::hash::Hash;

/// Sender channel type for transmitting packets to an interface.
pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
/// Receiver channel type for receiving transmission commands.
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

/// Sender channel type for receiving packets from an interface.
pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
/// Receiver channel type for packets received from an interface.
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

pub use crate::iface_messages::{RxMessage, TxMessage, TxMessageType};

/// A communication channel for an interface.
///
/// InterfaceChannel provides the send/receive channels for interacting
/// with an interface, along with its address and cancellation token.
pub struct InterfaceChannel {
    /// The unique address of this interface channel.
    pub address: AddressHash,
    /// Channel for receiving packets.
    pub rx_channel: InterfaceRxSender,
    /// Channel for transmitting packets.
    pub tx_channel: InterfaceTxReceiver,
    /// Token for stopping the interface.
    pub stop: CancellationToken,
}

impl InterfaceChannel {
    /// Creates a new receive channel pair.
    ///
    /// # Arguments
    ///
    /// * `cap` - The channel capacity (buffer size)
    ///
    /// # Returns
    ///
    /// A tuple of (sender, receiver)
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    /// Creates a new transmit channel pair.
    ///
    /// # Arguments
    ///
    /// * `cap` - The channel capacity (buffer size)
    ///
    /// # Returns
    ///
    /// A tuple of (sender, receiver)
    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    /// Creates a new InterfaceChannel with the given components.
    ///
    /// # Arguments
    ///
    /// * `rx_channel` - Channel for receiving packets
    /// * `tx_channel` - Channel for transmitting packets
    /// * `address` - The interface address
    /// * `stop` - Cancellation token for stopping
    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
        }
    }

    /// Returns a reference to the interface address.
    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    /// Splits the channel into its sender and receiver components.
    ///
    /// This consumes the channel and returns the receive and transmit
    /// channels separately.
    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

/// Trait for interface implementations.
///
/// Implement this trait to create custom interfaces for Reticulum.
/// Each interface must provide its Maximum Transmission Unit (MTU).
pub trait Interface {
    /// Returns the Maximum Transmission Unit (MTU) for this interface.
    ///
    /// The MTU determines the maximum packet size that can be transmitted
    /// without fragmentation.
    fn mtu() -> usize;
}

/// Internal representation of a local interface.
struct LocalInterface {
    address: AddressHash,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
}

/// Context for an interface implementation.
///
/// This provides the interface implementation with access to its
/// communication channels and cancellation token.
pub struct InterfaceContext<T: Interface> {
    /// The interface implementation.
    pub inner: Arc<StdMutex<T>>,
    /// The interface's communication channel.
    pub channel: InterfaceChannel,
    /// Token for stopping the interface.
    pub cancel: CancellationToken,
}

/// Manager for all interfaces in Reticulum.
///
/// InterfaceManager handles creating, spawning, and coordinating
/// multiple interface instances. It provides async channel-based
/// communication between interfaces and the transport layer.
pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
}

impl InterfaceManager {
    /// Creates a new InterfaceManager.
    ///
    /// # Arguments
    ///
    /// * `rx_cap` - Capacity of the receive channel
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::iface::InterfaceManager;
    ///
    /// let manager = InterfaceManager::new(100);
    /// ```
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
        }
    }

    /// Creates a new interface channel.
    ///
    /// This allocates a new channel with a unique address for
    /// communication with a specific interface.
    ///
    /// # Arguments
    ///
    /// * `tx_cap` - Capacity of the transmit channel
    ///
    /// # Returns
    ///
    /// A new InterfaceChannel for the interface
    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.counter += 1;

        let counter_bytes = self.counter.to_le_bytes();
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&counter_bytes[..]));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {}", address);

        let stop = CancellationToken::new();

        self.ifaces.push(LocalInterface {
            address,
            tx_send,
            stop: stop.clone(),
        });

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
        }
    }

    /// Creates a new interface context.
    ///
    /// # Arguments
    ///
    /// * `inner` - The interface implementation
    ///
    /// # Returns
    ///
    /// An InterfaceContext wrapping the implementation
    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        let channel = self.new_channel(1);

        let inner = Arc::new(StdMutex::new(inner));

        let context = InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
        };

        context
    }

    /// Spawns an interface worker task.
    ///
    /// This creates a new interface context and spawns the worker
    /// as an async task.
    ///
    /// # Arguments
    ///
    /// * `inner` - The interface implementation
    /// * `worker` - An async function that processes the interface
    ///
    /// # Returns
    ///
    /// The address of the spawned interface
    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.new_context(inner);
        let address = context.channel.address().clone();

        spawn(worker(context));

        address
    }

    /// Returns a reference to the global receive channel.
    pub fn receiver(&self) -> Arc<Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    /// Cleans up cancelled/stopped interfaces.
    ///
    /// Removes any interfaces whose stop token has been cancelled
    /// from the active interface list.
    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    /// Sends a packet to appropriate interfaces.
    ///
    /// Based on the TxMessageType, this either broadcasts the packet
    /// to all interfaces (except optionally excluded one) or sends
    /// it directly to a specific interface.
    ///
    /// # Arguments
    ///
    /// * `message` - The transmission message containing packet and type
    pub async fn send(&self, message: TxMessage) {
        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }

                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if should_send && !iface.stop.is_cancelled() {
                let _ = iface.tx_send.send(message.clone()).await;
            }
        }
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
