//! Reticulum identity demo — two link options:
//! - **`esp_now`** (default): ESP32-S3 internal Wi‑Fi + ESP-NOW.
//! - **`halow`**: T-HaLow TX-AH module on UART1, GPIO4 = RX, GPIO5 = TX (same as Arduino demo).
//!
//! Build for LilyGO T-HaLow:
//! `cargo build --release --no-default-features --features halow`

#![no_std]
#![no_main]

use esp_alloc as _;
use esp_backtrace as _;

mod beacon;

#[cfg(feature = "halow")]
mod halow;

#[cfg(all(feature = "esp_now", feature = "halow"))]
compile_error!("Enable only one of: `esp_now`, `halow`.");

#[cfg(not(any(feature = "esp_now", feature = "halow")))]
compile_error!("Enable feature `esp_now` or `halow`.");

use embassy_executor::Spawner;

#[cfg(feature = "esp_now")]
#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    esp_now_main(spawner).await
}

#[cfg(feature = "halow")]
#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    halow_main(spawner).await
}

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

// ─── ESP-NOW (default) ─────────────────────────────────────────────────────

#[cfg(feature = "esp_now")]
async fn esp_now_main(spawner: Spawner) -> ! {
    use embassy_time::{Duration, Ticker};
    use esp_hal::{clock::CpuClock, rng::Rng, timer::timg::TimerGroup};
    use esp_println::println;
    use esp_wifi::{
        esp_now::EspNowManager,
        init,
        EspWifiController,
    };
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };
    use reticulum::identity::PrivateIdentity;

    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut hrng = Rng::new(peripherals.RNG);

    let init = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, hrng.clone(), peripherals.RADIO_CLK).unwrap()
    );

    let wifi = peripherals.WIFI;
    let esp_now = esp_wifi::esp_now::EspNow::new(init, wifi).unwrap();
    println!("esp-now version {:?}", esp_now.version());

    use esp_hal::timer::systimer::SystemTimer;
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    esp_hal_embassy::init(systimer.alarm0);

    let mut seed = [0u8; 32];
    hrng.fill_bytes(&mut seed);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let private_id = PrivateIdentity::new_from_rand(&mut rng);
    beacon::print_local_addr(&private_id);

    let (manager, sender, receiver) = esp_now.split();
    let manager = mk_static!(EspNowManager<'static>, manager);
    let sender = mk_static!(
        embassy_sync::mutex::Mutex<
            embassy_sync::blocking_mutex::raw::NoopRawMutex,
            esp_wifi::esp_now::EspNowSender<'static>,
        >,
        embassy_sync::mutex::Mutex::new(sender)
    );

    spawner
        .spawn(peer_loop(manager, receiver, sender))
        .expect("peer_loop");
    spawner
        .spawn(beacon_broadcast(sender, private_id))
        .expect("beacon_broadcast");

    let mut idle = Ticker::every(Duration::from_secs(60));
    loop {
        idle.next().await;
    }
}

#[cfg(feature = "esp_now")]
#[embassy_executor::task]
async fn beacon_broadcast(
    sender: &'static embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        esp_wifi::esp_now::EspNowSender<'static>,
    >,
    private_id: reticulum::identity::PrivateIdentity,
) {
    use embassy_time::{Duration, Ticker};
    use esp_println::println;
    use esp_wifi::esp_now::BROADCAST_ADDRESS;
    let mut buf = [0u8; 256];
    let n = beacon::encode_beacon(&private_id, &mut buf).expect("beacon fits");
    let mut ticker = Ticker::every(Duration::from_secs(1));
    loop {
        ticker.next().await;
        let mut s = sender.lock().await;
        let st = s.send_async(&BROADCAST_ADDRESS, &buf[..n]).await;
        println!("beacon broadcast status: {:?}", st);
    }
}

#[cfg(feature = "esp_now")]
#[embassy_executor::task]
async fn peer_loop(
    manager: &'static esp_wifi::esp_now::EspNowManager<'static>,
    mut receiver: esp_wifi::esp_now::EspNowReceiver<'static>,
    sender: &'static embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        esp_wifi::esp_now::EspNowSender<'static>,
    >,
) {
    use embassy_futures::select::{select, Either};
    use embassy_time::{Duration, Ticker};
    use esp_println::println;
    use esp_wifi::esp_now::BROADCAST_ADDRESS;

    let mut ticker = Ticker::every(Duration::from_millis(500));
    loop {
        match select(receiver.receive_async(), ticker.next()).await {
            Either::First(r) => {
                let data = r.data();
                if data.len() >= 132 {
                    if let Some(peer_id) = beacon::decode_beacon(data) {
                        let peer_addr = peer_id.address_hash;
                        println!(
                            "Reticulum beacon from peer address hash: {}",
                            peer_addr.to_hex_string()
                        );
                        if r.info.dst_address == BROADCAST_ADDRESS {
                            maybe_add_peer(manager, &r.info.src_address);
                        }
                        continue;
                    }
                }
                if data.len() < 132 {
                    println!("RX {} bytes (short / non-beacon)", data.len());
                }
                if r.info.dst_address == BROADCAST_ADDRESS {
                    maybe_add_peer(manager, &r.info.src_address);
                }
            }
            Either::Second(_) => {
                let peer = match manager.fetch_peer(false) {
                    Ok(p) => p,
                    Err(_) => match manager.fetch_peer(true) {
                        Ok(p) => p,
                        Err(_) => continue,
                    },
                };
                println!("unicast hello to ESP-NOW peer {:?}", peer.peer_address);
                let mut s = sender.lock().await;
                let st = s
                    .send_async(
                        &peer.peer_address,
                        b"hello from Reticulum demo (ESP-NOW unicast)",
                    )
                    .await;
                println!("unicast status: {:?}", st);
            }
        }
    }
}

#[cfg(feature = "esp_now")]
fn maybe_add_peer(manager: &esp_wifi::esp_now::EspNowManager<'static>, src: &[u8; 6]) {
    use esp_println::println;
    use esp_wifi::esp_now::PeerInfo;
    if !manager.peer_exists(src) {
        manager
            .add_peer(PeerInfo {
                peer_address: *src,
                lmk: None,
                channel: None,
                encrypt: false,
            })
            .unwrap();
        println!("Added ESP-NOW peer {:?}", src);
    }
}

// ─── HaLow UART (T-HaLow board) ────────────────────────────────────────────

#[cfg(feature = "halow")]
async fn halow_main(spawner: Spawner) -> ! {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::mutex::Mutex;
    use embassy_time::{Duration, Ticker};
    use esp_hal::{clock::CpuClock, rng::Rng};
    use esp_hal::uart::{Config, Uart};
    use esp_hal::Async;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };
    use reticulum::identity::PrivateIdentity;

    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(72 * 1024);

    use esp_hal::timer::systimer::SystemTimer;
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    esp_hal_embassy::init(systimer.alarm0);

    let mut hrng = Rng::new(peripherals.RNG);
    let mut seed = [0u8; 32];
    hrng.fill_bytes(&mut seed);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let private_id = PrivateIdentity::new_from_rand(&mut rng);
    beacon::print_local_addr(&private_id);

    let mut uart = Uart::new(peripherals.UART1, Config::default())
        .expect("uart1")
        .with_rx(peripherals.GPIO4)
        .with_tx(peripherals.GPIO5);

    let mut eth_header = halow::default_eth_header();
    halow::configure_radio(&mut uart);
    halow::fetch_mac_into_header(&mut uart, &mut eth_header);

    let uart = uart.into_async();
    let uart = mk_static!(
        Mutex<NoopRawMutex, Uart<'static, Async>>,
        Mutex::new(uart)
    );

    spawner
        .spawn(halow_loop(uart, eth_header, private_id))
        .expect("halow_loop");

    let mut idle = Ticker::every(Duration::from_secs(3600));
    loop {
        idle.next().await;
    }
}

#[cfg(feature = "halow")]
#[embassy_executor::task]
async fn halow_loop(
    uart: &'static embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        esp_hal::uart::Uart<'static, esp_hal::Async>,
    >,
    eth_header: [u8; halow::ETH_HEADER_LEN],
    private_id: reticulum::identity::PrivateIdentity,
) {
    use embassy_time::{Duration, Instant, Timer};
    use core::sync::atomic::{AtomicU32, Ordering};
    use esp_println::println;
    const HALOW_VERBOSE_LOGS: bool = false;
    const HALOW_ALLOW_UNVERIFIED: bool = false;

    static INVALID_FRAME_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static TX_BEACON_LOGGED: AtomicU32 = AtomicU32::new(0);
    /// Log only occasional TX lines so the “first up” node is not dominated by `HaLow beacon TX`.
    static TX_STATUS_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static RX_DISCARD_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);

    let mut rx_accum = [0u8; 2048];
    let mut rx_len = 0usize;
    let mut last_byte = Instant::now();
    let boot = Instant::now();
    let mut log_event: u32 = 0;
    macro_rules! tlog {
        ($($arg:tt)*) => {{
            let ms = Instant::now().duration_since(boot).as_millis();
            log_event = log_event.wrapping_add(1);
            println!("[t={:>8}ms e={:06}] {}", ms, log_event, format_args!($($arg)*));
        }};
    }
    macro_rules! vlog {
        ($($arg:tt)*) => {{
            if HALOW_VERBOSE_LOGS {
                tlog!($($arg)*);
            }
        }};
    }
    let addr = private_id.as_identity().address_hash.as_slice();
    let phase_ms = 150u64 + (addr[0] as u64 % 700); // 150..849 ms
    let period_ms = 900u64 + (addr[1] as u64 % 400); // 900..1299 ms
    let startup_listen_ms = 2000u64 + (addr[2] as u64 % 1200); // 2000..3199 ms
    let mut jitter_state = u32::from_le_bytes([addr[12], addr[13], addr[14], addr[15]]);
    if jitter_state == 0 {
        jitter_state = 0x6d2b79f5;
    }
    tlog!(
        "HaLow beacon schedule startup_listen={}ms phase={}ms period={}ms",
        startup_listen_ms, phase_ms, period_ms
    );
    let mut next_beacon =
        Instant::now() + Duration::from_millis(startup_listen_ms + phase_ms);

    loop {
        Timer::after(Duration::from_millis(1)).await;

        // Drain UART RX until empty each tick (avoids starving RX vs. beacon TX).
        loop {
            let mut u = uart.lock().await;
            let mut tmp = [0u8; 256];
            let n = u.read_buffered_bytes(&mut tmp).unwrap_or(0);
            drop(u);
            if n == 0 {
                break;
            }
            for b in &tmp[..n] {
                if rx_len < rx_accum.len() {
                    rx_accum[rx_len] = *b;
                    rx_len += 1;
                }
            }
            last_byte = Instant::now();
        }

        let now = Instant::now();

        if now >= next_beacon {
            // Avoid transmitting while UART RX is active; overlapping AT+TXDATA with incoming
            // +RXDATA chatter increases framing loss on some modules.
            let rx_quiet = now.duration_since(last_byte) >= Duration::from_millis(40);
            if rx_len > 0 || !rx_quiet {
                next_beacon = now + Duration::from_millis(35);
                continue;
            }
            let mut buf = [0u8; 320];
            let n = beacon::encode_beacon_hex(&private_id, &mut buf).expect("beacon");
            if TX_BEACON_LOGGED.fetch_add(1, Ordering::Relaxed) == 0 {
                if let Some((body, sig)) = beacon::beacon_hex_checksums(&buf[..n]) {
                    vlog!("TX beacon checksums body={:08x} sig={:08x}", body, sig);
                }
                let self_verify = beacon::decode_beacon_hex_verbose(&buf[..n]).is_ok();
                vlog!("TX beacon self-verify: {}", self_verify);
            }
            let mut u = uart.lock().await;
            let r = halow::send_to_halow_async(&mut u, &eth_header, &buf[..n]).await;
            let tc = TX_STATUS_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
            if tc < 4 || tc % 16 == 0 {
                tlog!("HaLow beacon TX: {:?}", r);
            }
            // Simple deterministic PRNG jitter to avoid long-lived phase lock.
            jitter_state ^= jitter_state << 13;
            jitter_state ^= jitter_state >> 17;
            jitter_state ^= jitter_state << 5;
            let jitter_ms = (jitter_state as u64) % 240; // 0..239 ms
            next_beacon = now + Duration::from_millis(period_ms + jitter_ms);
        }

        if rx_len > 1800 {
            tlog!("RX overflow {} bytes, discarding", rx_len);
            rx_len = 0;
            continue;
        }

        if rx_len > 0 {
            let idle = if halow::reticulum_beacon_incomplete(&rx_accum[..rx_len]) {
                Duration::from_millis(150)
            } else {
                Duration::from_millis(100)
            };
            if now.duration_since(last_byte) >= idle {
                while rx_len > 0 {
                    match halow::try_take_beacon_frame(&rx_accum[..rx_len]) {
                        Some((frame, consumed)) => {
                            let mut decoded = None;
                            if frame.len() >= halow::ETH_HEADER_LEN + beacon::BEACON_HEX_LEN {
                                decoded = beacon::decode_beacon_hex(
                                    &frame[halow::ETH_HEADER_LEN
                                        ..halow::ETH_HEADER_LEN + beacon::BEACON_HEX_LEN],
                                );
                            }
                            if decoded.is_none() && frame.len() >= beacon::BEACON_HEX_LEN {
                                for off in 0..=frame.len() - beacon::BEACON_HEX_LEN {
                                    if let Some(peer_id) =
                                        beacon::decode_beacon_hex(
                                            &frame[off..off + beacon::BEACON_HEX_LEN],
                                        )
                                    {
                                        decoded = Some(peer_id);
                                        break;
                                    }
                                }
                            }

                            if let Some(peer_id) = decoded {
                                tlog!(
                                    "Peer Reticulum address hash: {}",
                                    peer_id.address_hash.to_hex_string()
                                );
                            } else {
                                let mut unverified_peer = None;
                                if HALOW_ALLOW_UNVERIFIED {
                                    // Optional fallback for bring-up: identity from beacon shape
                                    // when signature does not verify.
                                    if frame.len() >= halow::ETH_HEADER_LEN + beacon::BEACON_HEX_LEN {
                                        let payload = &frame
                                            [halow::ETH_HEADER_LEN..halow::ETH_HEADER_LEN + beacon::BEACON_HEX_LEN];
                                        unverified_peer = beacon::decode_beacon_hex_unverified(payload);
                                    }
                                    if unverified_peer.is_none() && frame.len() >= beacon::BEACON_HEX_LEN {
                                        for off in 0..=frame.len() - beacon::BEACON_HEX_LEN {
                                            if let Some(peer_id) = beacon::decode_beacon_hex_unverified(
                                                &frame[off..off + beacon::BEACON_HEX_LEN],
                                            ) {
                                                unverified_peer = Some(peer_id);
                                                break;
                                            }
                                        }
                                    }
                                }
                                let recovered_unverified = unverified_peer.is_some();
                                if let Some(peer_id) = unverified_peer {
                                    vlog!(
                                        "Peer Reticulum address hash (UNVERIFIED): {}",
                                        peer_id.address_hash.to_hex_string()
                                    );
                                }

                                // Only log when *nothing* recovered (avoid noise after UNVERIFIED / verified miss).
                                if !recovered_unverified {
                                    let c = INVALID_FRAME_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
                                    if c % 8 == 0 {
                                        let magic_off = frame
                                            .windows(beacon::BEACON_MAGIC.len())
                                            .position(|w| w == beacon::BEACON_MAGIC);
                                        if frame.len() >= halow::ETH_HEADER_LEN {
                                            let payload = &frame[halow::ETH_HEADER_LEN..];
                                            let payload_magic = payload
                                                .windows(beacon::BEACON_MAGIC.len())
                                                .position(|w| w == beacon::BEACON_MAGIC);
                                            let decode_reason = if payload.len() >= beacon::BEACON_HEX_LEN {
                                                beacon::decode_beacon_hex_verbose(
                                                    &payload[..beacon::BEACON_HEX_LEN],
                                                )
                                                .err()
                                            } else {
                                                None
                                            };
                                            let checksums = beacon::beacon_hex_checksums(payload);
                                            vlog!(
                                                "RX beacon-shaped frame len={} (no peer recovered) magic_off={:?} payload_magic_off={:?} decode_reason={:?} checksums={:?} first16={:02x?}",
                                                frame.len(),
                                                magic_off,
                                                payload_magic,
                                                decode_reason,
                                                checksums,
                                                &frame[..frame.len().min(16)]
                                            );
                                        } else {
                                            vlog!(
                                                "RX invalid short frame len={} magic_off={:?} first16={:02x?}",
                                                frame.len(),
                                                magic_off,
                                                &frame[..frame.len().min(16)]
                                            );
                                        }
                                    }
                                }
                            }
                            rx_accum.copy_within(consumed..rx_len, 0);
                            rx_len -= consumed;
                        }
                        None => {
                            // If we cannot assemble a frame and the buffer grows large, keep only
                            // the tail to avoid getting stuck on non-RXDATA UART noise forever.
                            if rx_len > 1024 {
                                let keep = 256usize;
                                let start = rx_len - keep;
                                rx_accum.copy_within(start..rx_len, 0);
                                rx_len = keep;
                            }
                            break;
                        }
                    }
                }
                if rx_len > 0 {
                    // Tiny fragments are common UART chatter; drop quietly to reduce log noise.
                    if rx_len < 16 {
                        rx_len = 0;
                        continue;
                    }
                    if halow::reticulum_beacon_incomplete(&rx_accum[..rx_len]) {
                        if now.duration_since(last_byte) >= Duration::from_secs(5) {
                            tlog!("RX stale {} bytes, discarding", rx_len);
                            rx_len = 0;
                        }
                    } else {
                        // Be tolerant to split/shifted UART boundaries: keep a tail so the next
                        // read can complete a partial `+RXDATA:` header or frame.
                        let d = RX_DISCARD_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
                        if d < 6 || d % 24 == 0 {
                            tlog!("RX discard {} bytes (assemble failed)", rx_len);
                        }
                        if rx_len > 192 {
                            let keep = 192usize;
                            let start = rx_len - keep;
                            rx_accum.copy_within(start..rx_len, 0);
                            rx_len = keep;
                        } else {
                            // Small leftovers are usually chatter; clear them.
                            rx_len = 0;
                        }
                    }
                }
            }
        }
    }
}
