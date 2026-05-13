//! One `embassy_executor::Executor` per OS thread; each thread runs [`reticulum::transport_embedded::EmbeddedTransport`]
//! (real `transport_engine` routing). Virtual “RF” bridges egress → `std::sync::mpsc` → peer `inject_from_interface`.

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
struct ThreadReport {
    tag: &'static str,
    acks: Option<Vec<Vec<u8>>>,
    stats: EmbeddedTransportStats,
}

#[test]
fn two_os_threads_two_embassy_executors_exchange_data_via_embedded_transport() {
    let (ab_tx, ab_rx) = mpsc::channel::<RxMessage>();
    let (ba_tx, ba_rx) = mpsc::channel::<RxMessage>();
    let (report_tx, report_rx) = mpsc::channel::<ThreadReport>();

    let rpt_a = report_tx.clone();
    std::thread::spawn(move || run_executor_a(ab_tx, ba_rx, rpt_a));

    let rpt_b = report_tx;
    std::thread::spawn(move || run_executor_b(ba_tx, ab_rx, rpt_b));

    let mut got_a = None;
    let mut got_b = None;
    let deadline = StdDuration::from_secs(8);
    let start = std::time::Instant::now();
    while got_a.is_none() || got_b.is_none() {
        if start.elapsed() > deadline {
            panic!("timed out waiting for node reports (a={got_a:?} b={got_b:?})");
        }
        match report_rx.recv_timeout(StdDuration::from_millis(100)) {
            Ok(r) => match r.tag {
                "a" => got_a = Some(r),
                "b" => got_b = Some(r),
                _ => {}
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    let a = got_a.expect("node A report");
    let b = got_b.expect("node B report");
    let acks = a.acks.expect("node A should return ack payloads");
    assert_eq!(
        acks,
        vec![b"ack-1".to_vec(), b"ack-2".to_vec(), b"ack-3".to_vec()]
    );
    assert_node_stats("node-a", a.stats);
    assert_node_stats("node-b", b.stats);
}

fn run_executor_a(
    to_b: mpsc::Sender<RxMessage>,
    from_b: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<ThreadReport>,
) {
    let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
    executor.run(|spawner| {
        reticulum::async_backend::embassy::set_spawner(spawner);
        spawner.spawn(node_a_entry(to_b, from_b, report)).unwrap();
    });
}

fn run_executor_b(
    to_a: mpsc::Sender<RxMessage>,
    from_a: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<ThreadReport>,
) {
    let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
    executor.run(|spawner| {
        reticulum::async_backend::embassy::set_spawner(spawner);
        spawner.spawn(node_b_entry(to_a, from_a, report)).unwrap();
    });
}

#[embassy_executor::task(pool_size = 4)]
async fn node_a_entry(
    to_b: mpsc::Sender<RxMessage>,
    from_b: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<ThreadReport>,
) {
    let node_a_addr = AddressHash::new_from_slice(b"mesh-sim-mt-node-a");
    let node_b_addr = AddressHash::new_from_slice(b"mesh-sim-mt-node-b");
    let node_a = make_node(node_a_addr);
    let sp = Spawner::for_current_executor().await;
    sp.spawn(virtual_air_out(node_a_addr, node_b_addr, node_a, to_b))
        .unwrap();
    sp.spawn(virtual_air_in(node_a, from_b)).unwrap();

    let acks = run_node_a_client(node_a_addr, node_b_addr, node_a).await;
    Timer::after(Duration::from_millis(50)).await;
    let _ = report.send(ThreadReport {
        tag: "a",
        acks: Some(acks),
        stats: node_a.stats(),
    });
}

#[embassy_executor::task(pool_size = 4)]
async fn node_b_entry(
    to_a: mpsc::Sender<RxMessage>,
    from_a: mpsc::Receiver<RxMessage>,
    report: mpsc::Sender<ThreadReport>,
) {
    let node_a_addr = AddressHash::new_from_slice(b"mesh-sim-mt-node-a");
    let node_b_addr = AddressHash::new_from_slice(b"mesh-sim-mt-node-b");
    let node_b = make_node(node_b_addr);
    let sp = Spawner::for_current_executor().await;
    sp.spawn(virtual_air_out(node_b_addr, node_a_addr, node_b, to_a))
        .unwrap();
    sp.spawn(virtual_air_in(node_b, from_a)).unwrap();
    sp.spawn(node_b_echo_app(node_b_addr, node_a_addr, node_b))
        .unwrap();
    sp.spawn(b_stats_report(node_b, report)).unwrap();
}

fn make_node(local_address: AddressHash) -> &'static EmbeddedTransport {
    Box::leak(Box::new(EmbeddedTransport::new(EmbeddedTransportConfig {
        channel_capacity: 32,
        broadcast_enabled: true,
        local_address: Some(local_address),
        ..EmbeddedTransportConfig::default()
    })))
}

#[embassy_executor::task(pool_size = 4)]
async fn virtual_air_out(
    from_addr: AddressHash,
    to_addr: AddressHash,
    from: &'static EmbeddedTransport,
    tx: mpsc::Sender<RxMessage>,
) {
    let mut egress = EmbeddedTransportPort::egress_receiver(from);
    loop {
        if let Ok(message) = egress.recv().await {
            if should_deliver(message.tx_type, to_addr) {
                let _ = tx.send(RxMessage {
                    address: from_addr,
                    packet: message.packet,
                });
            }
        }
    }
}

#[embassy_executor::task(pool_size = 4)]
async fn virtual_air_in(node: &'static EmbeddedTransport, rx: mpsc::Receiver<RxMessage>) {
    loop {
        match rx.try_recv() {
            Ok(msg) => node.inject_from_interface(msg),
            Err(mpsc::TryRecvError::Empty) => Timer::after(Duration::from_millis(1)).await,
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
}

async fn run_node_a_client(
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

#[embassy_executor::task(pool_size = 4)]
async fn node_b_echo_app(
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

#[embassy_executor::task(pool_size = 4)]
async fn b_stats_report(
    node_b: &'static EmbeddedTransport,
    report: mpsc::Sender<ThreadReport>,
) {
    Timer::after(Duration::from_millis(600)).await;
    let _ = report.send(ThreadReport {
        tag: "b",
        acks: None,
        stats: node_b.stats(),
    });
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
