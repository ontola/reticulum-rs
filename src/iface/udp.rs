//! UDP interface for Reticulum.
//!
//! This module provides a UDP interface for transmitting and receiving
//! Reticulum packets over UDP datagrams.
//!
//! # Overview
//!
//! UdpInterface binds to a local address and can optionally forward packets
//! to a remote address. Unlike TCP, UDP is connectionless and each packet
//! is sent as an independent datagram.
//!
//! # Usage
//!
//! ```ignore
//! use reticulum::iface::InterfaceManager;
//! use reticulum::iface::udp::UdpInterface;
//!
//! let mut manager = InterfaceManager::new(100);
//! manager.spawn(
//!     UdpInterface::new("0.0.0.0:4242", Some("192.168.1.100:4242")),
//!     UdpInterface::spawn
//! );
//! ```

use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = true;

/// A UDP interface for Reticulum networking.
///
/// UdpInterface provides UDP-based packet transmission and reception.
/// It can bind to a local address and optionally forward packets
/// to a remote UDP address.
pub struct UdpInterface {
    /// The local address to bind to.
    bind_addr: String,
    /// Optional remote address to forward packets to.
    forward_addr: Option<String>,
}

impl UdpInterface {
    /// Creates a new UDP interface.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The local address to bind to (e.g., "0.0.0.0:4242")
    /// * `forward_addr` - Optional remote address to forward packets to
    pub fn new<T: Into<String>>(bind_addr: T, forward_addr: Option<T>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            forward_addr: forward_addr.map(Into::into),
        }
    }

    /// Spawns the UDP interface worker task.
    ///
    /// This is the main async task that handles:
    /// - Binding to the local UDP socket
    /// - Receiving packets from the socket
    /// - Optionally forwarding packets to a remote address
    /// - Automatic reconnection on socket errors
    pub async fn spawn(context: InterfaceContext<Self>) {
        let bind_addr = { context.inner.lock().unwrap().bind_addr.clone() };
        let forward_addr = { context.inner.lock().unwrap().forward_addr.clone() };
        let iface_address = context.channel.address;

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let socket = UdpSocket::bind(bind_addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if let Err(_) = socket {
                log::info!("udp_interface: couldn't bind to <{}>", bind_addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let socket = socket.unwrap();
            let read_socket = Arc::new(socket);
            let write_socket = read_socket.clone();

            log::info!("udp_interface bound to <{}>", bind_addr);

            const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 3;

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let socket = read_socket;
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        let mut rx_buffer = [0u8; BUFFER_SIZE];

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            result = socket.recv_from(&mut rx_buffer) => {
                                match result {
                                    Ok((0, _)) => {
                                        log::warn!("udp_interface: connection closed");
                                        stop.cancel();
                                        break;
                                    }
                                    Ok((n, _in_addr)) => {
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&rx_buffer[..n])) {
                                            if PACKET_TRACE {
                                                log::trace!("udp_interface: rx << ({}) {}", iface_address, packet);
                                            }
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                        } else {
                                            log::warn!("udp_interface: couldn't decode packet");
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("udp_interface: connection error {}", e);
                                        break;
                                    }
                                }
                            },
                        };
                    }
                })
            };

            if let Some(forward_addr) = forward_addr.clone() {
                // Start transmit task
                let tx_task = {
                    let cancel = cancel.clone();
                    let tx_channel = tx_channel.clone();
                    let socket = write_socket;

                    tokio::spawn(async move {
                        loop {
                            if stop.is_cancelled() {
                                break;
                            }

                            let mut tx_buffer = [0u8; BUFFER_SIZE];

                            let mut tx_channel = tx_channel.lock().await;

                            tokio::select! {
                                _ = cancel.cancelled() => {
                                        break;
                                }
                                _ = stop.cancelled() => {
                                        break;
                                }
                                Some(message) = tx_channel.recv() => {
                                    let packet = message.packet;
                                    if PACKET_TRACE {
                                        log::trace!("udp_interface: tx >> ({}) {}", iface_address, packet);
                                    }
                                    let mut output = OutputBuffer::new(&mut tx_buffer);
                                    if let Ok(_) = packet.serialize(&mut output) {
                                        let _ = socket.send_to(output.as_slice(), &forward_addr).await;
                                    }
                                }
                            };
                        }
                    })
                };
                tx_task.await.unwrap();
            }

            rx_task.await.unwrap();

            log::info!("udp_interface <{}>: closed", bind_addr);
        }
    }
}

impl Interface for UdpInterface {
    /// Returns the Maximum Transmission Unit (MTU) for this interface.
    ///
    /// The UDP interface supports packets up to 2048 bytes.
    fn mtu() -> usize {
        2048
    }
}
