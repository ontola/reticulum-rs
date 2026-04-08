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
cargo run --release --no-default-features --features halow --target xtensa-esp32s3-none-elf
```

Notes:
- `--release` is strongly recommended by `esp-hal`.
- Repository root crate has `default = []` (no default embedded feature).
- `minimal-embassy` is the active hardware bring-up app for this flow.

## What this currently validates on hardware

- Embedded target dependency graph resolves and flashes on ESP32-S3.
- HaLow module AT configuration / UART TX-RX path works.
- Two-node beacon exchange works (`Peer Reticulum address hash: ...` observed).
- Beacon signature verification path works in steady state.

It does **not** yet validate full Reticulum `Transport` runtime on Embassy.

## Useful variants

Embedded compile-only check (no flash):

```sh
cargo check --release --no-default-features --features halow --target xtensa-esp32s3-none-elf
```

Core crate no-std check:

```sh
cargo check --lib --no-default-features --features alloc
```

Host demo run (desktop):

```sh
cargo run --target aarch64-apple-darwin --features std --bin my_code_demo
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
- `minimal-embassy` currently validates embedded link/beacon behavior, not full transport runtime.
