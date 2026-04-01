# Embedded Runbook (ESP32-S3)

This runbook captures the current known-good way to build and flash the
`embassy` example on ESP32-S3 for this repository.

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

## Known-good command

From repository root:

```sh
cargo run --release --example embassy
```

Notes:
- `--release` is strongly recommended by `esp-hal`.
- `embedded` is the default feature set in this repository.

## What this currently validates

- Embedded target dependency graph resolves correctly.
- Example compiles for `xtensa-esp32s3-none-elf`.
- Binary flashes and boots.
- Serial output confirms app entry (for example: `reticulum embassy bootstrap on esp32s3`).

It does **not** yet validate full Reticulum transport runtime on Embassy.

## Useful variants

Embedded compile-only check (no flash):

```sh
cargo check --example embassy --target xtensa-esp32s3-none-elf
```

No-std core library check:

```sh
cargo check --lib
```

Host demo run (desktop):

```sh
cargo run --target aarch64-apple-darwin --features std --bin my_code_demo
```

## Why these feature settings exist

- `std` feature:
  - Enables Tokio/networking/gRPC/logging paths intended for host runtime.
  - Enables `rand_core/getrandom` and `serde/std`.

- `embedded` feature:
  - Enables ESP/Embassy stack.
  - Intentionally avoids `std` dependencies.

- `alloc` feature:
  - Enables heap-backed core types in no-std mode.

## Common errors and fixes

### Symptom: `cargo run` executes `target/debug/my_code_demo`
Cause:
- Missing or wrong root `.cargo/config.toml`.
Fix:
- Create/fix root `.cargo/config.toml` to use xtensa target and espflash runner.

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

Check whether Tokio is present in embedded graph:

```sh
cargo tree --target xtensa-esp32s3-none-elf --no-default-features --features embedded -i tokio -e features
```

Expected result: no Tokio entries.

## Current milestone status

- Stage A extraction of runtime-agnostic transport decisions is in progress.
- Embedded bootstrap path is now working on hardware.
- Next milestone is moving more transport behavior behind runtime-agnostic seams,
  then introducing Embassy runtime execution for those seams.
