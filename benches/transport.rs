use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use reticulum::destination::link::Link;
use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::iface::{InterfaceManager, TxMessage, TxMessageType};
use reticulum::identity::PrivateIdentity;
use reticulum::packet::{Packet, PacketDataBuffer, PropagationType};
use tokio::runtime::{Builder, Runtime};

fn sample_packet() -> Packet {
    let mut packet = Packet::default();
    packet.header.propagation_type = PropagationType::Transport;
    packet.destination = AddressHash::new_from_hash(&reticulum::hash::Hash::new_from_slice(
        b"bench-send-destination",
    ));
    packet.data = PacketDataBuffer::new_from_slice(b"hello over reticulum");
    packet
}

fn sample_destination() -> SingleInputDestination {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    SingleInputDestination::new(identity, DestinationName::new("bench", "destination"))
}

fn sample_announce() -> Packet {
    sample_destination()
        .announce(OsRng, Some(b"bench announce payload"))
        .expect("announce packet")
}

fn activated_link() -> Link {
    let remote_destination = sample_destination();
    let (event_tx, _) = tokio::sync::broadcast::channel(16);

    let mut out_link = Link::new(remote_destination.desc, event_tx.clone());
    let request = out_link.request();

    let mut in_link = Link::new_from_request(
        &request,
        remote_destination.sign_key().clone(),
        remote_destination.desc,
        event_tx,
    )
    .expect("link from request");

    let proof = in_link.prove();
    let activation = out_link.handle_packet(&proof, true);
    black_box(activation);

    out_link
}

fn spawn_interface_drainers(
    runtime: &Runtime,
    manager: &mut InterfaceManager,
    count: usize,
) -> Vec<AddressHash> {
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let channel = manager.new_channel(1024);
        let address = channel.address;
        let (_rx_send, mut tx_recv) = channel.split();

        runtime.spawn(async move {
            while tx_recv.recv().await.is_some() {}
        });

        addresses.push(address);
    }

    addresses
}

fn transport_benchmarks(c: &mut Criterion) {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut group = c.benchmark_group("transport");

    let mut direct_manager = InterfaceManager::new(1);
    let direct_addrs = spawn_interface_drainers(&runtime, &mut direct_manager, 1);
    let direct_msg = TxMessage {
        tx_type: TxMessageType::Direct(direct_addrs[0]),
        packet: sample_packet(),
    };
    group.bench_function("interface_send_direct_one_iface", |b| {
        b.iter(|| {
            runtime.block_on(direct_manager.send(black_box(direct_msg)));
        });
    });

    let mut broadcast_manager = InterfaceManager::new(1);
    spawn_interface_drainers(&runtime, &mut broadcast_manager, 4);
    let broadcast_msg = TxMessage {
        tx_type: TxMessageType::Broadcast(None),
        packet: sample_packet(),
    };
    group.bench_function("interface_send_broadcast_four_ifaces", |b| {
        b.iter(|| {
            runtime.block_on(broadcast_manager.send(black_box(broadcast_msg)));
        });
    });

    let destination = sample_destination();
    group.bench_function("single_destination_announce_create", |b| {
        b.iter(|| {
            let packet = destination
                .announce(OsRng, Some(black_box(b"bench announce payload")))
                .expect("announce packet");
            black_box(packet);
        });
    });

    let announce = sample_announce();
    group.bench_function("single_destination_announce_validate", |b| {
        b.iter(|| {
            let validated = DestinationAnnounce::validate(black_box(&announce))
                .expect("valid announce");
            black_box(validated);
        });
    });

    let hash_packet = sample_packet();
    group.bench_function("packet_hash", |b| {
        b.iter(|| {
            let hash = black_box(&hash_packet).hash();
            black_box(hash);
        });
    });

    let mut request_link = activated_link();
    group.bench_function("link_request_create", |b| {
        b.iter(|| {
            let packet = request_link.request();
            black_box(packet);
        });
    });

    let link = activated_link();
    group.bench_function("link_data_packet_32b", |b| {
        b.iter(|| {
            let packet = link.data_packet(black_box(b"hello from link data packet path"))
                .expect("link packet");
            black_box(packet);
        });
    });

    let link_large = activated_link();
    let large_payload = [0x5au8; 256];
    group.bench_function("link_data_packet_256b", |b| {
        b.iter(|| {
            let packet = link_large
                .data_packet(black_box(&large_payload))
                .expect("link packet");
            black_box(packet);
        });
    });

    let proof_link = activated_link();
    let proof_hash = sample_packet().hash();
    group.bench_function("link_message_proof", |b| {
        b.iter(|| {
            let packet = proof_link.message_proof(black_box(proof_hash));
            black_box(packet);
        });
    });

    group.finish();
}

criterion_group!(benches, transport_benchmarks);
criterion_main!(benches);
