# Stage C: Async Backend Adapter

## Goal

Introduce an adapter layer so we can replace `tokio` primitives (std) with an
Embassy/no-std backend for embedded.

The first step is *mechanical*: move direct `tokio` usages behind a small
`async_backend` module, without changing behavior for `std`.

## Why this matters for UDP-on-ESP

To run `examples/udp_link.rs`-style logic on the ESP32-S3, we eventually need:

- `Transport` async runtime support (spawn/sleep/select, channels, cancellation)
- `iface` async runtime support (send/recv channels, spawning interface workers)

This stage only sets up the seam so we can later swap implementations.

## What we changed so far (this step)

1. Added `src/async_backend.rs` (std implementation only)
   - re-exports:
     - `broadcast`, `Mutex`, `MutexGuard`
     - `CancellationToken`
     - `time::{sleep, Instant}`
   - provides:
     - `spawn(...)` wrapper
     - `async_select!` macro aliasing `tokio::select!`

2. Updated `src/lib.rs`
   - exposes `async_backend` only under `cfg(feature = "std")`

3. Updated `src/transport.rs`
   - replaced direct `tokio::...` imports with `crate::async_backend::...`
   - replaced:
     - `tokio::spawn(...)` -> `crate::async_backend::spawn(...)`
     - `tokio::select!` -> `async_select!`
     - `tokio::time::sleep` -> `time::sleep`

## Tests run

- `cargo check --no-default-features --features std` (passes; warnings only)

## Next milestones

1. Implement an embedded backend in `src/async_backend.rs`
   - `Mutex` / channel / cancellation / sleep / spawn / select equivalents
2. Refactor `src/iface.rs` to use `async_backend` too
3. Start embedded UDP smoke test (keep networking minimal at first)
4. Implement the actual embedded UDP interface in Stage D

## Notes

This stage does not yet make embedded transport fully runnable; it creates the
adapter seam so the embedded backend swap becomes feasible.

