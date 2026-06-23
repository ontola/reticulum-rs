# T-Halow → Standalone Relay Node Checklist

Goal: LilyGO T-Halow running `reticulum-rs` on-device as a **standalone transport relay**
that can forward Reticulum traffic for other PrepNet nodes over HaLow.

**Current baseline:** Stage D/E bring-up — custom identity beacons, embedded transport seam,
and `stage-e-msg:` test payloads. Not a production relay yet.

**Reference implementations:**

| Path | Role |
|------|------|
| `t-halow/src/` | Integrated ESP router (this checklist) |
| `t-halow-bridge/src/main.rs` | On-air wire format: `ETH_HEADER` + **HDLC-framed** Reticulum bytes |
| `src/iface/serial.rs` | Host pattern: `Packet::serialize` → HDLC → wire |
| `src/transport_embedded.rs` | Embedded runner (Stage D/E) |
| `docs/stage-e-embedded-messaging.md` | Active messaging milestone |

---

## Milestone 0 — Align docs and harness naming

Docs still say `minimal-embassy/`; the harness is now `t-halow/`.

- [ ] Update `reticulum-rs/docs/embedded-runbook.md` paths → `t-halow/`
- [ ] Update `docs/stage-d-embedded-runtime.md` and `docs/stage-e-embedded-messaging.md`
- [ ] Expand `t-halow/README.md` with relay goal, wire format, and link to this checklist
- [ ] Note in README that `t-halow` ≠ `t-halow-bridge` (integrated router vs USB dongle)

**Done when:** A new agent can flash from `t-halow/` without hunting for `minimal-embassy`.

---

## Milestone 1 — Proper HaLow packet interface (blocker)

Today `halow_loop` sends `tx_msg.packet.data` raw and RX only understands beacons +
`stage-e-msg:`. A relay needs the same on-air payload as `t-halow-bridge`:

```text
AT+TXDATA → ETH_HEADER (14 B) + HDLC(Packet::serialize())
+RXDATA    → strip ETH_HEADER → HDLC decode → Packet::deserialize → transport ingress
```

### 1a. New module `t-halow/src/iface_halow.rs` (or extend `halow.rs`)

- [ ] Add `halow_tx_packet(uart, eth_header, packet: &Packet) -> Result`
  - `Packet::serialize()` into `OutputBuffer` (`src/serde.rs`, `no_std` + `alloc`)
  - `Hdlc::encode()` (`src/iface/hdlc.rs` — verify `no_std`; port if needed)
  - Reuse existing `send_to_halow_async` chunked TX path
- [ ] Add `halow_rx_try_take_packet(buf) -> Option<(Packet, consumed)>`
  - Reuse `try_take_beacon_frame` / `rxdata_header` framing
  - Strip `ETH_HEADER_LEN`, HDLC decode, `Packet::deserialize`
- [ ] Keep **identity beacon** path separate (custom `RNS0` hex) until replaced by real
  `Announce` packets on wire (see 1c)

### 1b. Wire `main.rs` halow_loop

- [ ] **Egress:** replace `payload = tx_msg.packet.data` with full packet serialize path
- [ ] **Ingress:** for non-beacon frames, `Packet::deserialize` →
  `embedded_transport.inject_from_interface(RxMessage { address: peer_iface, packet })`
  using peer address hash from path table / last hop, not `last_verified_peer` alone
- [ ] Remove or gate `stage-e-msg:` special case once real `Data` packets work

### 1c. Beacon strategy (pick one)

- [ ] **Option A (interop-first):** Stop custom hex beacons; emit real Reticulum `Announce`
  packets via transport egress (matches `t-halow-bridge-test` semantics)
- [ ] **Option B (transition):** Keep `RNS0` beacons for discovery *and* add serialized
  announces — document dual-format until A is proven

**Done when:** Two `t-halow` boards exchange **serialized** `Announce` + `Data` packets
without `stage-e-msg:` markers, and a third board running `t-halow-bridge-test` can
receive announces from an integrated node (interop smoke test).

**Files:** `t-halow/src/main.rs`, `t-halow/src/halow.rs`, new `iface_halow.rs`,
possibly `src/iface/hdlc.rs` (confirm `no_std`).

---

## Milestone 2 — Relay policy enabled

Transport forwarding logic exists in `transport_embedded.rs` but is gated off in firmware.

### 2a. Production config profile in `main.rs`

- [ ] Add `RELAY_MODE: bool` (or `cfg` feature) replacing scattered `STAGE_D_*` toggles
- [ ] When `RELAY_MODE`:
  - `broadcast_enabled: true`
  - `retransmit_enabled: true`
  - `STAGE_D_BOARD_PROOF_MODE: false`
  - `STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC: false`
  - `STAGE_D_ENABLE_LINK_LIFECYCLE_SYNTHETIC_TRAFFIC: false`
  - `STAGE_E_ENABLE_MINIMAL_MESSAGE_FLOW: false` (or repurpose for app-layer test only)
- [ ] Increase channel/cache sizes for relay load (measure under soak):
  - `channel_capacity` (16 → 32+)
  - `duplicate_cache_size`, `path_state_cache_size`, `intermediate_link_table_size`
  - `STAGE_D_HEAP_BYTES` if egress queues pressure the allocator

### 2b. Verify forwarding counters on hardware

- [ ] Three-board line: A — B (relay) — C
- [ ] On relay B, status logs show:
  - `data_forward_candidate_count` / `data_forward_queued_count` increasing
  - `link_request_forward_queued_count` when links traverse relay
  - `egress_dropped` / `event_dropped` stable under light load
- [ ] `EmbeddedEvent::DataRouted` with `route: Forward` and `forward_queued: true`

**Done when:** Node A sends `Data` to C through B; C logs local delivery; B does not
deliver locally (forward only).

**Files:** `t-halow/src/main.rs`, `src/transport_embedded.rs` (only if policy gaps found).

---

## Milestone 3 — Stage E completion (route / link parity)

Per `docs/stage-e-embedded-messaging.md` and `docs/current-status.md`.

### 3a. Route-state audit

- [ ] Compare embedded caches vs std `PathTable` / `LinkTable` in `src/transport.rs`
- [ ] List gaps that block multi-hop relay (document in this file under **Known gaps**)
- [ ] Port smallest missing pieces into `transport_embedded.rs` via shared
  `transport_engine.rs` helpers — no embedded-only policy forks

### 3b. Real messaging (not test markers)

- [ ] Replace `stage-e-msg:` with link-established `Data` or destination API
- [ ] Handle `EmbeddedEvent::DataRouted { route: DeliverLocal, .. }` for app hook
  (even a no-op log proves delivery path)
- [ ] Per-packet `source_address` on ingress from deserialized packet header, not
  `last_verified_peer` approximation

### 3c. Host sim regression before each board test

- [ ] `cargo test -p reticulum-mesh-sim` — embassy multi-hop tests green
- [ ] `cargo test -p reticulum-rs --features embedded` (or documented no-std check)

**Done when:** Stage E definition of done in `docs/stage-e-embedded-messaging.md` is met
on two boards **and** relay scenario from Milestone 2 passes.

---

## Milestone 4 — Persistent identity

Ephemeral keys per boot break stable addressing for a deployed relay.

- [ ] Choose store: ESP NVS via `esp-storage` / `embedded-storage`, or raw flash sector
- [ ] `t-halow/src/identity_store.rs`: load-or-create `PrivateIdentity`
- [ ] Wire boot in `main.rs` before `beacon::print_local_addr`
- [ ] Document factory-reset / wipe procedure in README

**Done when:** Reboot preserves `Local Reticulum address hash:` across power cycles.

---

## Milestone 5 — Radio config alignment

`t-halow` and `t-halow-bridge` use different AT profiles today — nodes may not hear each other.

| Setting | `t-halow` (`halow.rs`) | `t-halow-bridge` |
|---------|------------------------|------------------|
| Mode | `AT+MODE=GROUP` + `SSID=Mesh1` | `AT+MODE=GROUP` + `JOINGROUP` |
| Channel | `FREQ_RANGE=8630,8640`, `PRI_CHAN=1` | `CHAN_LIST=8680` |
| Eth dst | broadcast `ff:ff:…` | multicast `11:22:33:44:55:66` |

- [ ] Pick one EU profile for all PrepNet HaLow firmware
- [ ] Extract shared constants or document mandatory match
- [ ] Two-node RF ping: `t-halow` ↔ `t-halow-bridge` raw frame visible on both sides

**Done when:** Integrated node and bridge dongle on same desk see each other's `+RXDATA`.

---

## Milestone 6 — Operational relay hardening

- [ ] Watchdog / panic recovery (optional `esp-hal` WDT)
- [ ] Rate-limit status logs in relay mode (current `tlog!` is verbose)
- [ ] Soak test: 30+ min three-node relay, monitor `egress_dropped`, `rx_buf`, UART discards
- [ ] Memory budget table in README (heap, stacks, channel depths)
- [ ] Throughput note: UART AT ~70 kbps practical ceiling (`docs/technology/verslag.md`)

**Done when:** Relay runs overnight without panic; drops are bounded and documented.

---

## Milestone 7 — Minimal relay acceptance test (final DoD)

Reproducible procedure for `docs/embedded-runbook.md`:

1. Flash **Node A**, **Node B (relay)**, **Node C** from `t-halow/` with `RELAY_MODE`
2. A and C are edge nodes; B only forwards (no local app traffic)
3. A establishes path to C (announces visible on all three)
4. A sends application `Data` to C
5. C receives; B shows forward counters, not `data_deliver_local`
6. Power-cycle B; identity and forwarding recover within N seconds

- [ ] Document expected log lines in runbook
- [ ] Capture one known-good serial log excerpt in `t-halow/` or `docs/`

---

## Suggested implementation order

```text
M0 (docs) ──► M1 (packet iface) ──► M5 (radio align) ──► M2 (relay policy)
                                                      └──► M3 (Stage E)
M4 (identity) can parallel M2–M3
M6–M7 after M2 passes on hardware
```

**Smallest vertical slice:** M1 + M5 + M2 with two boards (A and B as relay for a host
node via `t-halow-bridge-test`) before investing in three-board line topology.

---

## Known gaps (fill as you go)

| Gap | Owner file | Notes |
|-----|------------|-------|
| Egress sends `packet.data` only | `t-halow/src/main.rs` ~L460 | Must serialize full `Packet` |
| RX no `Packet::deserialize` | `t-halow/src/main.rs` ~L538 | Only beacons + stage-e-msg |
| `broadcast_enabled: false` | `t-halow/src/main.rs` ~L102 | Blocks rebroadcast |
| `retransmit_enabled: false` | `t-halow/src/main.rs` ~L106 | Blocks path-request retx |
| Staging toggles default on | `t-halow/src/main.rs` ~L19–27 | Proof mode, not relay |
| Ephemeral identity | `t-halow/src/main.rs` ~L80 | New key every boot |
| AT/radio profile mismatch | `halow.rs` vs `t-halow-bridge` | May block interop |
| Full std `Transport` not on ESP | `src/transport.rs` | Embedded runner is parallel seam |
| UART throughput | hardware | ~70 kbps; P4 SPI is long-term path |

---

## Out of scope (for this checklist)

- LXMF / application messaging on device
- ESP32-P4 SPI driver (`docs/technology/thalow.md`)
- AtomicServer or GovGrid services on ESP
- Python Reticulum interop CI gate
- Serial `Interface` on host for Pattern A (separate `t-halow-bridge` path)
