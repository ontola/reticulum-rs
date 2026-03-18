//! TCP server interface for Reticulum.
//!
//! This module provides a TCP server interface that listens for incoming
//! TCP connections and creates TCP clients for each connected peer.
//!
//! # Overview
//!
//! TcpServer binds to a local address and accepts incoming TCP connections.
//! For each new connection, it spawns a TcpClient to handle communication
//! with that peer.
//!
//! # Usage
//!
//! ```ignore
//! use reticulum::iface::InterfaceManager;
//! use reticulum::iface::tcp_server::TcpServer;
//!
//! let mut manager = InterfaceManager::new(100);
//! manager.spawn(
//!     TcpServer::new("0.0.0.0:4242", manager.clone()),
//!     TcpServer::spawn
//! );
//! ```

use alloc::string::String;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::RnsError;

use super::tcp_client::TcpClient;
use super::{Interface, InterfaceContext, InterfaceManager};

/// A TCP server interface for accepting incoming connections.
///
/// TcpServer listens on a local address and spawns TcpClient instances
/// for each connected peer. This allows Reticulum to accept incoming
/// TCP connections from remote peers.
pub struct TcpServer {
    /// The local address to bind to.
    addr: String,
    /// Reference to the interface manager for spawning clients.
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl TcpServer {
    /// Creates a new TCP server that will listen on the specified address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The local address to bind to (e.g., "0.0.0.0:4242")
    /// * `iface_manager` - Reference to the InterfaceManager for spawning client interfaces
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
        }
    }

    /// Spawns the TCP server interface worker task.
    ///
    /// This is the main async task that handles:
    /// - Binding to the local address
    /// - Accepting incoming TCP connections
    /// - Spawning TcpClient instances for each connected peer
    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = TcpListener::bind(addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if let Err(_) = listener {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            log::info!("tcp_server: listen on <{}>", addr);

            let listener = listener.unwrap();

            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();

            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }

                    client = listener.accept() => {
                        if let Ok(client) = client {
                            log::info!(
                                "tcp_server: new client <{}> connected to <{}>",
                                client.1,
                                addr
                            );

                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                TcpClient::new_from_stream(client.1.to_string(), client.0),
                                TcpClient::spawn,
                            );
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }
    }
}

impl Interface for TcpServer {
    /// Returns the Maximum Transmission Unit (MTU) for this interface.
    ///
    /// The TCP server interface supports packets up to 2048 bytes.
    fn mtu() -> usize {
        2048
    }
}
