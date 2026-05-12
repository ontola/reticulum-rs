#![cfg(feature = "embassy-virtual")]

use std::sync::mpsc;
use std::time::Duration as StdDuration;

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use reticulum::hash::AddressHash;
use reticulum::iface_messages::{RxMessage, TxMessageType};
use reticulum::packet::PacketType;
use reticulum::transport_embedded::{
    EmbeddedTransport, EmbeddedTransportConfig, EmbeddedTransportPort, EmbeddedTransportStats,
};

#[derive(Debug)]
struct MeshOutcome {
    acks: Vec<Vec<u8>>,
    node_a: EmbeddedTransportStats,
    node_b: EmbeddedTransportStats,
}

#[test]
fn embassy_virtual_nodes_exchange_packets_through_embedded_transport() {
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
        executor.run(|spawner| {
            reticulum::async_backend::set_spawner(spawner);
            spawner.spawn(mesh_regression(tx)).unwrap();
        });
    });

    let outcome = rx
        .recv_timeout(StdDuration::from_secs(5))
        .expect("virtual Embassy mesh test timed out");

    assert_eq!(
        outcome.acks,
        vec![b"ack-1".to_vec(), b"ack-2".to_vec(), b"ack-3".to_vec()]
    );

    assert_node_stats("node-a", outcome.node_a);
    assert_node_stats("node-b", outcome.node_b);
}

#[embassy_executor::task]
async fn mesh_regression(tx: mpsc::Sender<MeshOutcome>) {
    let node_a_addr = AddressHash::new_from_slice(b"test-embassy-node-a");
    let node_b_addr = AddressHash::new_from_slice(b"test-embassy-node-b");

    let node_a = make_node(node_a_addr);
    let node_b = make_node(node_b_addr);

    Spawner::for_current_executor()
        .await
        .spawn(virtual_air_link(node_a_addr, node_b_addr, node_a, node_b))
        .unwrap();
    Spawner::for_current_executor()
        .await
        .spawn(virtual_air_link(node_b_addr, node_a_addr, node_b, node_a))
        .unwrap();
    Spawner::for_current_executor()
        .await
        .spawn(node_b_app(node_b_addr, node_a_addr, node_b))
        .unwrap();

    let acks = run_node_a_app(node_a_addr, node_b_addr, node_a).await;

    Timer::after(Duration::from_millis(50)).await;

    tx.send(MeshOutcome {
        acks,
        node_a: node_a.stats(),
        node_b: node_b.stats(),
    })
    .unwrap();
}

fn make_node(local_address: AddressHash) -> &'static EmbeddedTransport {
    Box::leak(Box::new(EmbeddedTransport::new(EmbeddedTransportConfig {
        channel_capacity: 32,
        broadcast_enabled: true,
        local_address: Some(local_address),
        ..EmbeddedTransportConfig::default()
    })))
}

#[embassy_executor::task(pool_size = 2)]
async fn virtual_air_link(
    from_addr: AddressHash,
    to_addr: AddressHash,
    from: &'static EmbeddedTransport,
    to: &'static EmbeddedTransport,
) {
    let mut egress = EmbeddedTransportPort::egress_receiver(from);

    loop {
        if let Ok(message) = egress.recv().await {
            if should_deliver(message.tx_type, to_addr) {
                to.inject_from_interface(RxMessage {
                    address: from_addr,
                    packet: message.packet,
                });
            }
        }
    }
}

async fn run_node_a_app(
    node_a_addr: AddressHash,
    node_b_addr: AddressHash,
    node_a: &'static EmbeddedTransport,
) -> Vec<Vec<u8>> {
    let mut ingress = node_a.ingress_events();
    let messages = [
        b"hello from embedded node-a".as_slice(),
        b"node-a packet two".as_slice(),
        b"node-a final packet".as_slice(),
    ];
    let mut acks = Vec::new();

    for payload in messages {
        node_a.request_synthetic_bytes(PacketType::Data, node_b_addr, payload);

        loop {
            if let Ok(message) = ingress.recv().await {
                if message.packet.header.packet_type == PacketType::Data
                    && message.packet.destination == node_a_addr
                {
                    acks.push(message.packet.data.as_slice().to_vec());
                    break;
                }
            }
        }
    }

    acks
}

#[embassy_executor::task]
async fn node_b_app(
    node_b_addr: AddressHash,
    node_a_addr: AddressHash,
    node_b: &'static EmbeddedTransport,
) {
    let mut ingress = node_b.ingress_events();
    let mut ack_count = 0u8;

    loop {
        if let Ok(message) = ingress.recv().await {
            if message.packet.header.packet_type != PacketType::Data
                || message.packet.destination != node_b_addr
            {
                continue;
            }

            ack_count = ack_count.saturating_add(1);
            let ack = [b'a', b'c', b'k', b'-', b'0' + ack_count];
            node_b.request_synthetic_bytes(PacketType::Data, node_a_addr, &ack);
        }
    }
}

fn should_deliver(tx_type: TxMessageType, to_addr: AddressHash) -> bool {
    match tx_type {
        TxMessageType::Broadcast(exclude) => exclude.map(|addr| addr != to_addr).unwrap_or(true),
        TxMessageType::Direct(address) => address == to_addr,
    }
}

fn assert_node_stats(name: &str, stats: EmbeddedTransportStats) {
    assert_eq!(stats.interface_ingress_count, 3, "{name} ingress count");
    assert_eq!(stats.synthetic_ingress_count, 0, "{name} synthetic ingress");
    assert_eq!(stats.data_count, 3, "{name} data count");
    assert_eq!(stats.data_deliver_local_count, 3, "{name} local delivery");
    assert_eq!(stats.egress_generated_count, 3, "{name} egress generated");
    assert_eq!(stats.egress_dropped_count, 0, "{name} egress dropped");
    assert_eq!(stats.event_dropped_count, 0, "{name} event dropped");
}
