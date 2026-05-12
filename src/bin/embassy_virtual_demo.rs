use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use reticulum::hash::AddressHash;
use reticulum::packet::{Packet, PacketDataBuffer, PacketType};

static A_TO_B: Channel<CriticalSectionRawMutex, Frame, 8> = Channel::new();
static B_TO_A: Channel<CriticalSectionRawMutex, Frame, 8> = Channel::new();
static DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[derive(Clone, Copy)]
struct Frame {
    from: AddressHash,
    packet: Packet,
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let node_a = AddressHash::new_from_slice(b"virtual-embassy-node-a");
    let node_b = AddressHash::new_from_slice(b"virtual-embassy-node-b");

    spawner.spawn(node_a_task(node_a, node_b)).unwrap();
    spawner.spawn(node_b_task(node_b, node_a)).unwrap();

    DONE.wait().await;
    Timer::after(Duration::from_millis(50)).await;
    std::process::exit(0);
}

#[embassy_executor::task]
async fn node_a_task(node_a: AddressHash, node_b: AddressHash) {
    let messages = [
        b"hello from node-a".as_slice(),
        b"node-a packet two".as_slice(),
        b"node-a final packet".as_slice(),
    ];

    println!("node-a: up at {}", short_addr(node_a));

    for (index, message) in messages.iter().enumerate() {
        let packet = data_packet(node_b, message);
        A_TO_B
            .send(Frame {
                from: node_a,
                packet,
            })
            .await;

        println!(
            "node-a: sent {} to {}: {}",
            index + 1,
            short_addr(node_b),
            text(message)
        );

        let reply = B_TO_A.receive().await;
        println!(
            "node-a: received from {}: {}",
            short_addr(reply.from),
            text(reply.packet.data.as_slice())
        );

        Timer::after(Duration::from_millis(100)).await;
    }

    DONE.signal(());
}

#[embassy_executor::task]
async fn node_b_task(node_b: AddressHash, node_a: AddressHash) {
    println!("node-b: up at {}", short_addr(node_b));

    loop {
        let frame = A_TO_B.receive().await;
        if frame.packet.destination != node_b {
            println!(
                "node-b: dropped packet for {}",
                short_addr(frame.packet.destination)
            );
            continue;
        }

        let payload = frame.packet.data.as_slice();
        println!(
            "node-b: received from {}: {}",
            short_addr(frame.from),
            text(payload)
        );

        let mut ack = [0u8; 64];
        let ack_len = write_ack(&mut ack, payload);
        B_TO_A
            .send(Frame {
                from: node_b,
                packet: data_packet(node_a, &ack[..ack_len]),
            })
            .await;
    }
}

fn data_packet(destination: AddressHash, payload: &[u8]) -> Packet {
    let mut packet = Packet::default();
    packet.header.packet_type = PacketType::Data;
    packet.destination = destination;
    packet.data = PacketDataBuffer::new_from_slice(payload);
    packet
}

fn write_ack(out: &mut [u8], payload: &[u8]) -> usize {
    let prefix = b"ack: ";
    let prefix_len = prefix.len().min(out.len());
    out[..prefix_len].copy_from_slice(&prefix[..prefix_len]);

    let available = out.len().saturating_sub(prefix_len);
    let payload_len = payload.len().min(available);
    out[prefix_len..prefix_len + payload_len].copy_from_slice(&payload[..payload_len]);
    prefix_len + payload_len
}

fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("<non-utf8>")
}

fn short_addr(address: AddressHash) -> String {
    address.to_hex_string()[..8].to_string()
}
