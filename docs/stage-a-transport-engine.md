# Stage A: Transport Engine Extraction

## Goal

Start separating protocol decisions from runtime plumbing without a broad generic rewrite.

This stage is intentionally small: extract deterministic packet-ingress decision logic
into a runtime-agnostic module while keeping current Tokio behavior unchanged.

## Why this approach

- Avoids "generic runtime everywhere" complexity.
- Keeps working Tokio behavior as the source of truth.
- Creates a concrete seam for later Embassy integration.
- Enables unit testing of protocol decisions without async/runtime coupling.

## Non-goals for Stage A

- No replacement of Tokio channels, mutexes, spawn, or select loops.
- No full extraction of all transport state/handlers.
- No async trait abstraction over sockets or interface managers.
- No behavior changes to announce/link/proof/data handling.

## Design seam

We split packet handling into two parts:

1. **Ingress decision (pure, runtime-agnostic)**
   - What should happen with a just-received packet?
   - Should it be dropped early?
   - Should it be rebroadcast?
   - Which protocol handler should process it?

2. **Execution (runtime/plumbing-bound)**
   - Actually lock state.
   - Send packets/channels.
   - Run async handlers and side effects.

Stage A only extracts part (1).

## Files touched in Stage A

- `src/transport/engine.rs` (new)
  - Defines pure decision enums and decision function.
- `src/transport.rs`
  - Uses engine decision in packet receive loop.

## Engine API (Stage A)

- `IngressAction`: `Announce | LinkRequest | Proof | Data`
- `IngressDecision`:
  - `DropDuplicate`
  - `HandleFixedDestination`
  - `Dispatch { rebroadcast: bool, action: IngressAction }`
- `decide_ingress(...) -> IngressDecision`

Inputs are simple booleans and packet metadata only. No async, no runtime types.

## Behavior invariants

Stage A preserves existing behavior:

- Fixed destination packets are handled before duplicate filtering.
- Duplicate packets are dropped after fixed-destination check.
- Re-broadcast applies only when transport broadcast is enabled and packet type is not announce.
- Packet type still maps 1:1 to existing handlers.

## Definition of done (Stage A)

Stage A is complete when all of these are true:

- The main routing/policy choices in `transport.rs` are represented by pure engine decisions.
- `transport.rs` still owns execution details (locks, async sends, table mutation), but not policy branching.
- Existing behavior is unchanged for announce/link/proof/data flows.
- Engine decisions have focused unit tests for the accepted/denied routes.
- `cargo check --no-default-features --features alloc` succeeds for the crate.

Out of scope for Stage A (belongs to later stages):

- Moving runtime primitives (Tokio/Embassy tasks, channels, mutexes) behind adapters.
- Rewriting transport internals around traits or async abstraction layers.
- Moving all business logic into `engine.rs`.

## Progress checkpoint

Current Stage A status: complete.

Already extracted into engine decisions:

- Ingress routing and duplicate handling.
- Link-request route selection.
- Path-request route selection and circular-request detection.
- Announce discovery/retransmit branching.
- Proof forwarding and proof follow-up.
- Link data classification and keepalive-response gating.
- Link destination route and fixed-destination route selection.

Final audit:

- High-level ingress dispatch is engine-driven.
- Announce, path-request, link-request, proof, and data policy branches are engine-driven.
- Link maintenance timer/state transitions are engine-driven.
- Remaining logic in `transport.rs` is runtime-bound execution:
  async locking, send operations, table mutation, and logging.

## Follow-up stages (preview)

- **Stage B**: move more deterministic protocol transitions (still no runtime rewrites).
- **Stage C**: add adapter boundary for runtime-bound operations (send, timers, tasks).
- **Stage D**: implement Embassy driver against same protocol seam.
