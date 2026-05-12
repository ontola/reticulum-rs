//! LilyGO T-HaLow (TX-AH) — Reticulum identity demo over UART (GPIO4 RX / GPIO5 TX).
//!
//! Build (from this directory):
//! `cargo build --release --target xtensa-esp32s3-none-elf`

#![no_std]
#![no_main]

extern crate alloc;

use esp_alloc as _;
use esp_backtrace as _;

mod beacon;
mod halow;

const STAGE_D_HEAP_BYTES: usize = 160 * 1024;

const STAGE_D_BOARD_PROOF_MODE: bool = true;
const STAGE_D_RF_STABILITY_MODE: bool = true;
const STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC: bool = !STAGE_D_BOARD_PROOF_MODE;
const STAGE_D_ENABLE_LINK_LIFECYCLE_SYNTHETIC_TRAFFIC: bool = !STAGE_D_RF_STABILITY_MODE;
const STAGE_D_LINK_LIFECYCLE_SYNTH_EVERY_STATUS_TICKS: u32 = 3;
const STAGE_D_ENABLE_AUTO_PROBE_ON_ANNOUNCE: bool = true;
const STAGE_D_RETRANSMIT_ENABLED: bool = false;
const STAGE_D_SYNTHETIC_COOLDOWN_AFTER_PRESSURE_SECS: u64 = 20;
const STAGE_E_ENABLE_MINIMAL_MESSAGE_FLOW: bool = true;
const STAGE_E_MESSAGE_EVERY_STATUS_TICKS: u32 = 2;
const STAGE_E_MESSAGE_VARIANTS: [&[u8]; 3] = [
    b"stage-e-msg:hello-from-node",
    b"stage-e-msg:reticulum-embedded",
    b"stage-e-msg:board-flow-check",
];
const STAGE_E_MESSAGE_PREFIX: &[u8] = b"stage-e-msg:";

use embassy_executor::Spawner;

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

async fn halow_main(spawner: Spawner) -> ! {
    use alloc::sync::Arc;
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
    use reticulum::{async_backend, transport_embedded};

    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(STAGE_D_HEAP_BYTES);

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
    async_backend::set_spawner(spawner);
    let embedded_transport = Arc::new(transport_embedded::EmbeddedTransport::new(
        transport_embedded::EmbeddedTransportConfig {
            channel_capacity: 16,
            emit_probe_on_ingress_announce: false,
            broadcast_enabled: false,
            duplicate_cache_size: 128,
            path_state_cache_size: 64,
            known_hops_cache_size: 64,
            retransmit_enabled: STAGE_D_RETRANSMIT_ENABLED,
            local_address: Some(private_id.as_identity().address_hash),
            intermediate_link_table_size: 32,
        },
    ));
    // Stage D smoke policy is now command-driven, not implicit.
    embedded_transport.set_auto_probe_on_ingress_announce(STAGE_D_ENABLE_AUTO_PROBE_ON_ANNOUNCE);

    spawner
        .spawn(halow_loop(uart, eth_header, private_id, embedded_transport))
        .expect("halow_loop");

    let mut idle = Ticker::every(Duration::from_secs(3600));
    loop {
        idle.next().await;
    }
}

#[embassy_executor::task]
async fn halow_loop(
    uart: &'static embassy_sync::mutex::Mutex<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        esp_hal::uart::Uart<'static, esp_hal::Async>,
    >,
    eth_header: [u8; halow::ETH_HEADER_LEN],
    private_id: reticulum::identity::PrivateIdentity,
    embedded_transport: alloc::sync::Arc<reticulum::transport_embedded::EmbeddedTransport>,
) {
    use embassy_time::{Duration, Instant, Timer};
    use core::sync::atomic::{AtomicU32, Ordering};
    use esp_println::println;
    use reticulum::hash::AddressHash;
    use reticulum::packet::PacketType;
    use reticulum::transport_embedded::EmbeddedEvent;
    use reticulum::transport_engine::{SingleDataRoute, STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD};

    fn stage_e_payload_utf8(p: &[u8]) -> &str {
        core::str::from_utf8(p).unwrap_or("<non-utf8>")
    }

    const HALOW_VERBOSE_LOGS: bool = false;
    const HALOW_ALLOW_UNVERIFIED: bool = false;
    const HALOW_BEACON_FORCE_AFTER_DEFERRALS: u16 = 48;
    const HALOW_BEACON_FORCE_LOG_EVERY: u32 = 16;
    // Stage D seam toggles are module-level constants so both setup and loop use
    // the same behavior switch.

    static INVALID_FRAME_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static TX_BEACON_LOGGED: AtomicU32 = AtomicU32::new(0);
    /// Log only occasional TX lines so the “first up” node is not dominated by `HaLow beacon TX`.
    static TX_STATUS_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static RX_DISCARD_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static RX_DISCARD_BYTES_COUNTER: AtomicU32 = AtomicU32::new(0);
    static TX_FORCED_COUNTER: AtomicU32 = AtomicU32::new(0);
    static STAGE_D_INGRESS_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static STAGE_D_EGRESS_TX_LOG_COUNTER: AtomicU32 = AtomicU32::new(0);
    static STAGE_D_PERIODIC_KIND_COUNTER: AtomicU32 = AtomicU32::new(0);
    static STAGE_D_LINK_LIFECYCLE_KIND_COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut stage_d_egress_rx = embedded_transport.egress_receiver();
    let mut stage_d_events_rx = embedded_transport.events();
    let mut next_stage_d_status_log = Instant::now() + Duration::from_secs(5);
    let mut last_egress_dropped = 0u32;
    let mut last_event_dropped = 0u32;
    let mut synthetic_cooldown_until: Option<Instant> = None;
    let mut synthetic_stride: u8 = 1;
    let mut synthetic_clean_intervals: u8 = 0;
    let mut synthetic_status_tick: u32 = 0;
    let mut stage_e_status_tick: u32 = 0;
    let mut stage_e_msg_counter: usize = 0;
    let mut last_verified_peer: Option<AddressHash> = None;

    let mut rx_accum = [0u8; 2048];
    let mut rx_len = 0usize;
    let mut last_byte = Instant::now();
    let mut beacon_tx_deferrals: u16 = 0;
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
        "HaLow beacon schedule startup_listen={}ms phase={}ms period={}ms stage_d_board_proof_mode={} stage_d_rf_stability_mode={} stage_d_synth={} auto_probe={} retransmit={}",
        startup_listen_ms,
        phase_ms,
        period_ms,
        STAGE_D_BOARD_PROOF_MODE,
        STAGE_D_RF_STABILITY_MODE,
        STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC,
        STAGE_D_ENABLE_AUTO_PROBE_ON_ANNOUNCE,
        STAGE_D_RETRANSMIT_ENABLED
    );
    let mut next_beacon =
        Instant::now() + Duration::from_millis(startup_listen_ms + phase_ms);

    loop {
        let loop_sleep_ms = if STAGE_D_RF_STABILITY_MODE { 3 } else { 1 };
        Timer::after(Duration::from_millis(loop_sleep_ms)).await;

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

        if now >= next_stage_d_status_log {
            let s = embedded_transport.stats();
            let pressure_increased = s.egress_dropped_count > last_egress_dropped
                || s.event_dropped_count > last_event_dropped
            ;
            if pressure_increased {
                tlog!(
                    "StageD pressure warning: egress_dropped {}->{} event_dropped {}->{}",
                    last_egress_dropped,
                    s.egress_dropped_count,
                    last_event_dropped,
                    s.event_dropped_count
                );
                // Back off synthetic stimulation temporarily when channels show pressure.
                synthetic_cooldown_until = Some(
                    now + Duration::from_secs(STAGE_D_SYNTHETIC_COOLDOWN_AFTER_PRESSURE_SECS),
                );
                synthetic_clean_intervals = 0;
                let old = synthetic_stride;
                synthetic_stride = (synthetic_stride.saturating_mul(2)).min(8);
                if synthetic_stride != old {
                    tlog!(
                        "StageD synthetic pacing increased: every {} status tick(s)",
                        synthetic_stride
                    );
                }
            } else if synthetic_stride > 1 {
                // Gradually recover to normal pacing after clean intervals.
                synthetic_clean_intervals = synthetic_clean_intervals.saturating_add(1);
                if synthetic_clean_intervals >= 3 {
                    synthetic_clean_intervals = 0;
                    synthetic_stride /= 2;
                    tlog!(
                        "StageD synthetic pacing relaxed: every {} status tick(s)",
                        synthetic_stride
                    );
                }
            }
            tlog!(
                "StageD status iface_ingress={} synth_ingress={} announce={} data={} data_local={} data_fwd={} data_fwd_q={} lr_fwd_q={} link_tbl_ins={} link_tbl_dup={} proof_bp={} link_ka_bp={} path_req={} link_request={} proof={} pending={} activated={} egress_generated={} egress_dropped={} event_dropped={} rx_buf={} rx_discard={} rx_discard_bytes={} tx_forced={}",
                s.interface_ingress_count,
                s.synthetic_ingress_count,
                s.announce_count,
                s.data_count,
                s.data_deliver_local_count,
                s.data_forward_candidate_count,
                s.data_forward_queued_count,
                s.link_request_forward_queued_count,
                s.intermediate_link_insert_count,
                s.intermediate_link_duplicate_skip_count,
                s.link_proof_propagate_queued_count,
                s.link_keepalive_propagate_queued_count,
                s.path_request_count,
                s.link_request_count,
                s.proof_count,
                s.link_pending_count,
                s.link_activated_count,
                s.egress_generated_count,
                s.egress_dropped_count,
                s.event_dropped_count,
                rx_len,
                RX_DISCARD_LOG_COUNTER.load(Ordering::Relaxed),
                RX_DISCARD_BYTES_COUNTER.load(Ordering::Relaxed),
                TX_FORCED_COUNTER.load(Ordering::Relaxed)
            );
            last_egress_dropped = s.egress_dropped_count;
            last_event_dropped = s.event_dropped_count;
            if STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC {
                if let Some(until) = synthetic_cooldown_until {
                    if now < until {
                        tlog!(
                            "StageD synthetic cooldown active for ~{}s",
                            until.duration_since(now).as_secs()
                        );
                        next_stage_d_status_log = now + Duration::from_secs(5);
                        continue;
                    }
                    synthetic_cooldown_until = None;
                    tlog!("StageD synthetic cooldown ended");
                }
                synthetic_status_tick = synthetic_status_tick.wrapping_add(1);
                if synthetic_status_tick % u32::from(synthetic_stride) != 0 {
                    next_stage_d_status_log = now + Duration::from_secs(5);
                    continue;
                }
                // Exercise Stage D typed command path periodically.
                embedded_transport.request_probe(private_id.as_identity().address_hash);
                let kind = STAGE_D_PERIODIC_KIND_COUNTER.fetch_add(1, Ordering::Relaxed) % 4;
                let (ptype, payload): (PacketType, &'static [u8]) = match kind {
                    0 => (PacketType::Data, b"stage-d-synth-data"),
                    1 => (PacketType::Data, STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD),
                    2 => (PacketType::LinkRequest, b"stage-d-synth-link-request"),
                    _ => (PacketType::Proof, b"stage-d-synth-proof"),
                };
                embedded_transport.request_synthetic(
                    ptype,
                    private_id.as_identity().address_hash,
                    payload,
                );
                // Also inject staged ingress so Stage D counters/events cover more than announce-only RX.
                // This simulates "radio delivered this packet to transport runner".
                embedded_transport.inject_ingress_packet(
                    ptype,
                    private_id.as_identity().address_hash,
                    payload,
                );
            }
            if STAGE_D_ENABLE_LINK_LIFECYCLE_SYNTHETIC_TRAFFIC
                && synthetic_status_tick % STAGE_D_LINK_LIFECYCLE_SYNTH_EVERY_STATUS_TICKS == 0
            {
                let kind =
                    STAGE_D_LINK_LIFECYCLE_KIND_COUNTER.fetch_add(1, Ordering::Relaxed) % 2;
                let (ptype, payload): (PacketType, &'static [u8]) = match kind {
                    0 => (PacketType::LinkRequest, b"stage-d-lifecycle-link-request"),
                    _ => (PacketType::Proof, b"stage-d-lifecycle-proof"),
                };
                embedded_transport.inject_ingress_packet(
                    ptype,
                    private_id.as_identity().address_hash,
                    payload,
                );
                tlog!(
                    "StageD lifecycle synthetic ingress injected: {:?}",
                    ptype
                );
            }
            if STAGE_E_ENABLE_MINIMAL_MESSAGE_FLOW {
                stage_e_status_tick = stage_e_status_tick.wrapping_add(1);
                if stage_e_status_tick % STAGE_E_MESSAGE_EVERY_STATUS_TICKS == 0 {
                    if let Some(peer_dest) = last_verified_peer {
                        let payload = STAGE_E_MESSAGE_VARIANTS
                            [stage_e_msg_counter % STAGE_E_MESSAGE_VARIANTS.len()];
                        stage_e_msg_counter = stage_e_msg_counter.wrapping_add(1);
                        // Unicast application-style Data to the peer (A→B), not to self.
                        embedded_transport.request_synthetic(
                            PacketType::Data,
                            peer_dest,
                            payload,
                        );
                        tlog!(
                            "StageE message TX queued dest={} bytes={} text=\"{}\" raw={:?}",
                            peer_dest,
                            payload.len(),
                            stage_e_payload_utf8(payload),
                            payload
                        );
                    }
                }
            }
            next_stage_d_status_log = now + Duration::from_secs(5);
        }

        if let Ok(ev) = stage_d_events_rx.try_recv() {
            let c = STAGE_D_INGRESS_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
            match ev {
                EmbeddedEvent::AnnounceTriggeredPathRequest { destination, bytes } => {
                    // Keep this line explicit: it is the key Stage D board proof signal.
                    tlog!(
                        "StageD board-check: announce -> path-request egress destination={} bytes={}",
                        destination,
                        bytes
                    );
                }
                EmbeddedEvent::DataRouted {
                    route,
                    destination,
                    source,
                    forward_queued,
                } => {
                    if c < 8 || c % 32 == 0 {
                        tlog!(
                            "StageE data route: {:?} dest={} src={} fwd_q={}",
                            route,
                            destination,
                            source,
                            forward_queued
                        );
                    }
                    if route == SingleDataRoute::DeliverLocal
                        && source != AddressHash::new_empty()
                    {
                        if c < 16 || c % 32 == 0 {
                            tlog!(
                                "StageE: local Data delivery (from peer {})",
                                source.to_hex_string()
                            );
                        }
                    }
                }
                EmbeddedEvent::LinkRequestRouted {
                    route,
                    destination,
                    source,
                    forward_queued,
                    link_table_inserted,
                } => {
                    if c < 12 || c % 48 == 0 {
                        tlog!(
                            "StageE link-req route: {:?} dest={} src={} fwd_q={} link_tbl_ins={}",
                            route,
                            destination,
                            source,
                            forward_queued,
                            link_table_inserted
                        );
                    }
                }
                _ => {
                    if c < 3 || c % 64 == 0 {
                        tlog!("StageD event: {:?}", ev);
                    }
                }
            }
        }

        // Stage D seam smoke: egress packets emitted by embedded runner -> HaLow TX.
        if let Ok(tx_msg) = stage_d_egress_rx.try_recv() {
            let payload = tx_msg.packet.data.as_slice();
            if !payload.is_empty() {
                let mut u = uart.lock().await;
                let r = halow::send_to_halow_async(&mut u, &eth_header, payload).await;
                let c = STAGE_D_EGRESS_TX_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
                if c < 3 || c % 32 == 0 {
                    let s = embedded_transport.stats();
                    tlog!(
                        "StageD egress TX: {:?} ({} bytes, tx_type={:?}, generated={})",
                        r,
                        payload.len(),
                        tx_msg.tx_type,
                        s.egress_generated_count
                    );
                }
            }
        }

        if now >= next_beacon {
            // Avoid transmitting while UART RX is active; overlapping AT+TXDATA with incoming
            // +RXDATA chatter increases framing loss on some modules.
            let rx_quiet = now.duration_since(last_byte) >= Duration::from_millis(40);
            if rx_len > 0 || !rx_quiet {
                beacon_tx_deferrals = beacon_tx_deferrals.saturating_add(1);
                // Keep TX fairness: if RX stays busy for too long, force a beacon anyway so
                // both boards continue advertising and do not fall into asymmetric TX starvation.
                if beacon_tx_deferrals < HALOW_BEACON_FORCE_AFTER_DEFERRALS {
                    next_beacon = now + Duration::from_millis(35);
                    continue;
                }
                let forced = TX_FORCED_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
                if forced <= 3 || forced % HALOW_BEACON_FORCE_LOG_EVERY == 0 {
                    tlog!(
                        "HaLow beacon TX forced after {} RX-busy deferrals (count={})",
                        beacon_tx_deferrals,
                        forced
                    );
                }
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
            beacon_tx_deferrals = 0;
            // Simple deterministic PRNG jitter to avoid long-lived phase lock.
            jitter_state ^= jitter_state << 13;
            jitter_state ^= jitter_state >> 17;
            jitter_state ^= jitter_state << 5;
            let jitter_ms = (jitter_state as u64) % 240; // 0..239 ms
            let stability_extra_period_ms = if STAGE_D_RF_STABILITY_MODE { 450 } else { 0 };
            next_beacon =
                now + Duration::from_millis(period_ms + jitter_ms + stability_extra_period_ms);
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
                                last_verified_peer = Some(peer_id.address_hash);
                                // Stage D seam smoke: feed a minimal ingress event into the
                                // embedded transport runner whenever we get a verified peer beacon.
                                embedded_transport.inject_announce_from_interface(
                                    peer_id.address_hash,
                                    peer_id.address_hash,
                                );
                                let c = STAGE_D_INGRESS_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
                                if c < 3 || c % 32 == 0 {
                                    let s = embedded_transport.stats();
                                    tlog!(
                                        "StageD ingress counts iface_ingress={} synth_ingress={} announce={} data={} data_local={} data_fwd={} data_fwd_q={} lr_fwd_q={} link_tbl_ins={} link_tbl_dup={} proof_bp={} link_ka_bp={} path_req={} link_request={} proof={} pending={} activated={} egress_generated={} egress_dropped={} event_dropped={}",
                                        s.interface_ingress_count,
                                        s.synthetic_ingress_count,
                                        s.announce_count,
                                        s.data_count,
                                        s.data_deliver_local_count,
                                        s.data_forward_candidate_count,
                                        s.data_forward_queued_count,
                                        s.link_request_forward_queued_count,
                                        s.intermediate_link_insert_count,
                                        s.intermediate_link_duplicate_skip_count,
                                        s.link_proof_propagate_queued_count,
                                        s.link_keepalive_propagate_queued_count,
                                        s.path_request_count,
                                        s.link_request_count,
                                        s.proof_count,
                                        s.link_pending_count,
                                        s.link_activated_count,
                                        s.egress_generated_count,
                                        s.egress_dropped_count,
                                        s.event_dropped_count
                                    );
                                }
                            } else {
                                if frame.len() > halow::ETH_HEADER_LEN {
                                    let payload = &frame[halow::ETH_HEADER_LEN..];
                                    if payload.starts_with(STAGE_E_MESSAGE_PREFIX) {
                                        tlog!(
                                            "StageE message RX bytes={} text=\"{}\" raw={:?}",
                                            payload.len(),
                                            stage_e_payload_utf8(payload),
                                            payload
                                        );
                                        let source_address = last_verified_peer
                                            .unwrap_or(AddressHash::new_empty());
                                        embedded_transport.inject_ingress_packet_from_interface_bytes(
                                            source_address,
                                            PacketType::Data,
                                            private_id.as_identity().address_hash,
                                            payload,
                                        );
                                        rx_accum.copy_within(consumed..rx_len, 0);
                                        rx_len -= consumed;
                                        continue;
                                    }
                                }
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
                        if !halow::has_rxdata_prefix(&rx_accum[..rx_len]) {
                            // No `+RXDATA:` marker present yet: this is usually UART chatter/AT
                            // echo, not a partial frame. Keep only a tiny tail to avoid
                            // discard storms and let real markers enter quickly.
                            let keep = rx_len.min(64);
                            let start = rx_len - keep;
                            rx_accum.copy_within(start..rx_len, 0);
                            rx_len = keep;
                            continue;
                        }
                        // Be tolerant to split/shifted UART boundaries: keep a tail so the next
                        // read can complete a partial `+RXDATA:` header or frame.
                        let d = RX_DISCARD_LOG_COUNTER.fetch_add(1, Ordering::Relaxed);
                        if d < 6 || d % 24 == 0 {
                            tlog!("RX discard {} bytes (assemble failed)", rx_len);
                        }
                        RX_DISCARD_BYTES_COUNTER.fetch_add(rx_len as u32, Ordering::Relaxed);
                        let keep = rx_len.min(384);
                        let start = rx_len - keep;
                        rx_accum.copy_within(start..rx_len, 0);
                        rx_len = keep;
                    }
                }
            }
        }
    }
}
