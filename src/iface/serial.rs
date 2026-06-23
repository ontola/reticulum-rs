use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_serial::SerialPortBuilderExt;

use crate::async_backend::spawn;
use crate::async_backend::CancellationToken;
use crate::async_backend::Mutex;
use crate::async_select;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::{Interface, InterfaceContext};

const PACKET_TRACE: bool = false;

pub struct SerialInterface {
    port: String,
    baud_rate: u32,
}

impl SerialInterface {
    pub fn new(port: &str, baud_rate: u32) -> Self {
        Self {
            port: port.to_string(),
            baud_rate,
        }
    }

    pub async fn spawn(context: InterfaceContext<SerialInterface>) {
        let (port, baud_rate) = {
            let inner = context.inner.lock().unwrap();
            (inner.port.clone(), inner.baud_rate)
        };
        let iface_address = context.channel.address;
        let iface_stop = context.channel.stop.clone();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(Mutex::new(tx_channel));

        let stream = match tokio_serial::new(&port, baud_rate).open_native_async() {
            Ok(s) => s,
            Err(e) => {
                log::error!("serial: failed to open {} at {}: {}", port, baud_rate, e);
                iface_stop.cancel();
                return;
            }
        };

        log::info!("serial: opened {} at {} baud", port, baud_rate);

        let cancel = context.cancel.clone();
        let stop = CancellationToken::new();

        let (read_stream, write_stream) = tokio::io::split(stream);

        const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 2;

        let rx_task = {
            let cancel = cancel.clone();
            let stop = stop.clone();
            let mut stream = read_stream;
            let rx_channel = rx_channel.clone();

            spawn(async move {
                let mut hdlc_rx_buffer = [0u8; BUFFER_SIZE];
                let mut rx_buffer = [0u8; BUFFER_SIZE + (BUFFER_SIZE / 2)];
                let mut serial_buffer = [0u8; BUFFER_SIZE * 16];

                loop {
                    async_select! {
                        _ = cancel.cancelled() => {
                            break;
                        }
                        _ = stop.cancelled() => {
                            break;
                        }
                        result = stream.read(&mut serial_buffer[..]) => {
                            match result {
                                Ok(0) => {
                                    log::warn!("serial: port closed");
                                    stop.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    for &byte in serial_buffer.iter().take(n) {
                                        rx_buffer[BUFFER_SIZE - 1] = byte;

                                        let frame = Hdlc::find(&rx_buffer[..]);
                                        if let Some(frame) = frame {
                                            let frame_buffer = &mut rx_buffer[frame.0..frame.1+1];
                                            let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);
                                            if Hdlc::decode(frame_buffer, &mut output).is_ok() {
                                                if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(output.as_slice())) {
                                                    if PACKET_TRACE {
                                                        log::trace!("serial: rx << ({}) {}", iface_address, packet);
                                                    }
                                                    let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                } else {
                                                    log::warn!("serial: couldn't decode packet");
                                                }
                                            } else {
                                                log::warn!("serial: couldn't decode hdlc frame");
                                            }

                                            frame_buffer.fill(0);
                                        } else {
                                            rx_buffer.copy_within(1.., 0);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("serial: read error {}", e);
                                    stop.cancel();
                                    break;
                                }
                            }
                        },
                    };
                }
            })
        };

        let tx_task = {
            let cancel = cancel.clone();
            let mut stream = write_stream;

            spawn(async move {
                loop {
                    if stop.is_cancelled() {
                        break;
                    }

                    let mut hdlc_tx_buffer = [0u8; BUFFER_SIZE];
                    let mut tx_buffer = [0u8; BUFFER_SIZE];

                    let mut tx_channel = tx_channel.lock().await;

                    async_select! {
                        _ = cancel.cancelled() => {
                            break;
                        }
                        _ = stop.cancelled() => {
                            break;
                        }
                        Some(message) = tx_channel.recv() => {
                            let packet = message.packet;
                            if PACKET_TRACE {
                                log::trace!("serial: tx >> ({}) {}", iface_address, packet);
                            }
                            let mut output = OutputBuffer::new(&mut tx_buffer);
                            if packet.serialize(&mut output).is_ok() {
                                let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);
                                if Hdlc::encode(output.as_slice(), &mut hdlc_output).is_ok() {
                                    let _ = stream.write_all(hdlc_output.as_slice()).await;
                                    let _ = stream.flush().await;
                                }
                            }
                        }
                    };
                }
            })
        };

        tx_task.await.unwrap();
        rx_task.await.unwrap();

        log::info!("serial: closed {}", port);
        iface_stop.cancel();
    }
}

impl Interface for SerialInterface {
    fn mtu() -> usize {
        2048
    }
}
