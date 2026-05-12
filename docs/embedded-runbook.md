# Embedded Runbook (ESP32-S3 / T-HaLow)

This runbook captures the current known-good way to build and flash the
`minimal-embassy` app on ESP32-S3 for this repository.

## End Goal

The end goal is a single Reticulum protocol core whose deterministic behavior
is shared across host (`std`/Tokio) and embedded (`no_std`/Embassy) targets.
Runtime-specific concerns (tasks, timing, channels, I/O) are isolated behind
adapter seams, so embedded support is added by plugging in an Embassy backend
rather than rewriting protocol logic. The ESP32-S3 + T-HaLow path is the
primary embedded proving ground for this architecture.

## Prerequisites

- ESP Rust toolchain installed (via `espup`) and environment sourced.
- `espflash` installed.
- Board connected over USB.

## One-time setup checks

1. Ensure `.cargo/config.toml` exists in repo root.
2. Ensure it sets:
   - default target: `xtensa-esp32s3-none-elf`
   - runner: `espflash flash --monitor`

Without this, `cargo run` may run a host binary instead of flashing ESP.

## Known-good command (HaLow path)

From `minimal-embassy/`:

```sh
cargo run --release --target xtensa-esp32s3-none-elf
```

Notes:
- `--release` is strongly recommended by `esp-hal`.
- `minimal-embassy` is T-HaLow-only (no alternate radio backends).
- Repository root crate has `default = []` (no default embedded feature) when building the library from the repo root.

## Test ownership for Stage D

Use `minimal-embassy/` as the hardware test harness for Stage D.

- Existing communication wiring in `minimal-embassy/src/main.rs` is the base.
- New board tests (including upcoming `announce -> path request`) should be
  added on top of that base wiring.
- Shared core changes in `src/` are still required, but board validation is
  considered proven only through `minimal-embassy` runtime behavior/logs.

## What this currently validates on hardware

- Embedded target dependency graph resolves and flashes on ESP32-S3.
- HaLow module AT configuration / UART TX-RX path works.
- Two-node beacon exchange works (`Peer Reticulum address hash: ...` observed).
- Beacon signature verification path works in steady state.

It does **not** yet validate full Reticulum `Transport` runtime on Embassy.

## Stage D toggles (minimal-embassy)

In `minimal-embassy/src/main.rs`:

- `STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC`
  - `true`: every 5s, injects staged synthetic ingress + requests synthetic egress.
  - `false`: disables synthetic stimulation so logs reflect primarily real radio traffic.
- `STAGE_D_ENABLE_AUTO_PROBE_ON_ANNOUNCE`
  - `true`: Stage D runner auto-generates staged path-request egress when announce ingress is observed.
  - `false`: disables that automatic probe behavior.
- `STAGE_D_RETRANSMIT_ENABLED`
  - `true`: Stage D embedded runner enables retransmit-style path-request decision branch.
  - `false`: keeps recursive-broadcast-only behavior in current staged harness.

Expected board-check log when this path triggers:

- `StageD board-check: announce -> path-request egress destination=... bytes=...`

Recommended use:

- Two-node RF behavior checks: set both toggles to `false` for cleaner interpretation.
- Stage D seam verification/debug: set both toggles to `true` (default today).

Pressure behavior note:

- If Stage D drop counters increase (`egress_dropped` / `event_dropped`), the app now
  automatically pauses synthetic stimulation for a short cooldown window
  (`STAGE_D_SYNTHETIC_COOLDOWN_AFTER_PRESSURE_SECS` in `minimal-embassy/src/main.rs`).
- After pressure events, synthetic pacing also becomes less frequent automatically and
  later returns toward normal after clean intervals.

## Stage E message-flow toggles (minimal-embassy)

In `minimal-embassy/src/main.rs`:

- `STAGE_E_ENABLE_MINIMAL_MESSAGE_FLOW`
  - `true`: periodically emits Stage E message payloads via embedded egress path.
  - `false`: disables Stage E message injection and keeps Stage D-only behavior.
- `STAGE_E_MESSAGE_EVERY_STATUS_TICKS`
  - controls Stage E message pacing in units of Stage status intervals.
- `STAGE_E_MESSAGE_VARIANTS`
  - static payload set rotated for simple repeated A<->B message signatures.

Behavior notes:

- Stage E TX only runs after a **verified peer beacon** was decoded (`Peer Reticulum address hash: ...`).
  Packets are addressed to that peer’s destination hash (unicast), not to self.
- Periodic status includes `data_local=` / `data_fwd=` from shared single-destination data routing.

Current message marker:

- Stage E payloads are prefixed with `stage-e-msg:`.

## Stage E two-board message check (initial slice)

Goal: verify low-rate real payload exchange across two boards using the existing
HaLow harness and embedded runner seam.

1. Flash both boards from `minimal-embassy/` with:

```sh
cargo run --release --target xtensa-esp32s3-none-elf
```

2. Confirm baseline discovery logs on both:
   - `Peer Reticulum address hash: ...`

3. Confirm Stage E transmit logs appear (periodic, after peer discovery):
   - `StageE message TX queued dest=... bytes=... payload=...`

4. Confirm Stage E receive logs appear on at least one peer repeatedly:
   - `StageE message RX bytes=... payload=...`
   - Optional: `StageE data route: DeliverLocal ...` (receiver classifies ingress with shared policy)

5. Keep run active for several intervals and ensure:
   - no panic/reboot loop,
   - no sustained RX collapse,
   - Stage D pressure warnings do not continuously increase.

Expected interpretation:

- Seeing both TX and RX Stage E signatures indicates the initial message slice is
  active end-to-end through the current harness.
- Missing RX with present TX usually indicates framing/noise or peer sync issues;
  keep the run longer and verify beacon discovery remains steady.

## Useful variants

Embedded compile-only check (no flash):

```sh
cargo check --release --target xtensa-esp32s3-none-elf
```

Core crate no-std check:

```sh
cargo check --lib --no-default-features --features alloc
```

Host demo run (desktop):

```sh
cargo run --target aarch64-apple-darwin --features std --bin runtime_demo
```

## Why these feature settings exist

- `std` feature:
  - Enables Tokio/networking/gRPC/logging paths intended for host runtime.
  - Enables `rand_core/getrandom` and `serde/std`.

- `embedded` feature (root crate):
  - Enables ESP/Embassy dependencies in the root crate.
  - Intentionally avoids `std` dependencies.
  - Not used directly by the current `minimal-embassy` HaLow smoke flow.

- `alloc` feature:
  - Enables heap-backed core types in no-std mode.

## Common errors and fixes

### Symptom: `cargo run` executes host binary
Cause:
- Running from wrong directory and/or missing embedded target/runner config.
Fix:
- Run from `minimal-embassy/` and ensure `.cargo/config.toml` sets xtensa target + espflash runner.

### Symptom: `getrandom` unsupported target
Cause:
- `rand_core/getrandom` pulled into embedded build.
Fix:
- Keep `getrandom` only under crate `std` feature.

### Symptom: `serde_core` / `byteorder` / `std`-related explosion on xtensa
Cause:
- One or more dependencies built with default `std` features.
Fix:
- Keep no-std dependencies with `default-features = false` and add only required features.

### Symptom: Fernet errors around `Pkcs7` / `encrypt_padded_b2b_mut`
Cause:
- Missing `block-padding` feature on `cbc`.
Fix:
- Enable `cbc` feature `block-padding`.

### Symptom: Tokio appears in embedded dependency tree
Cause:
- Dev dependency leakage.
Fix:
- Keep Tokio dev-dependency host-gated (`cfg(not(target_arch = "xtensa"))`).

## Quick dependency sanity checks

Check whether Tokio is present in root embedded graph:

```sh
cargo tree --target xtensa-esp32s3-none-elf --no-default-features --features embedded -i tokio -e features
```

Expected result: no Tokio entries.

## Current milestone status

- Stage A: complete (engine-driven transport decisions extracted and tested).
- Stage B: in progress/advanced (more action decisions moved to engine seam).
- Stage C: async backend seam established (`async_backend`).
- Stage D: embedded runtime execution proof established on boards
  (`announce -> path-request` and staged lifecycle coverage).
- Stage E: see `docs/stage-e-embedded-messaging.md` for messaging-focused follow-up.
