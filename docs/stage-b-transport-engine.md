# Stage B: Transport Action Decisions

## Goal

Continue separating **deterministic protocol transitions** from runtime execution:

- Extract more “what should happen next?” logic into `src/transport/engine.rs`
- Keep “how to do it” (locks, async sends, table mutation, logging) in `src/transport.rs`

Stage B is intentionally incremental and does not introduce any new runtime abstraction layers.

## Why this approach

- Stage A proved the engine seam is workable and testable.
- Stage B reduces the remaining policy `match`/`if` branches inside `transport.rs` by converting them into explicit engine **action decisions**.
- Because the engine remains pure, we can validate behavior with fast unit tests.

## Non-goals for Stage B

- No generic runtime/async abstraction rewrite.
- No refactoring that moves async primitives (Tokio tasks, channels, mutexes) into the engine.
- No behavior changes to announce/link/proof/data protocol rules.
- No attempt to fully “move everything into `engine.rs`”.

## Design seam

We split “transport handling” into two parts again:

1. **Decision (pure, runtime-agnostic)**
   - Inputs: enums/results/flags/config values that already exist in protocol land
   - Output: a small action enum describing the deterministic follow-up
   - No side effects

2. **Execution (runtime/plumbing-bound)**
   - Transport performs side effects based on the engine’s chosen action:
     - call link/destination methods that mutate link state
     - send packets
     - update tables / trigger async work
     - logging

## What Stage B targets first

The highest-value next extraction is the “follow-up mapping” after link/destination processing.

### Example target: data-path follow-ups from `LinkHandleResult`

When `transport.rs` calls `link.handle_packet(...)`, it receives a `LinkHandleResult` such as:

- `KeepAlive`
- `MessageReceived(Some(proof))` (vs `MessageReceived(None)`)
- `Activated`
- `None`

Stage B will extract the deterministic mapping:

- `LinkHandleResult` -> `engine` follow-up action enum
- then `transport.rs` executes the side effects for the chosen action

This is the same extraction pattern already used in Stage A (for keepalive response gating and proof follow-up).

## Files touched in Stage B

- `src/transport/engine.rs`
  - Add new action enums and pure decision functions
  - Add focused unit tests (prefer table-driven tests for scenario coverage)
- `src/transport.rs`
  - Replace remaining deterministic policy branches with calls into the engine
  - Keep async/IO/table mutation logic in place

## Engine API (Stage B)

New engine pieces will follow a consistent style:

- A small enum that names actions explicitly (e.g. `SendKeepAliveResponse`, `SendProof`, `NoOp`)
- A pure function `decide_*` that returns that enum from the minimal inputs required
- Unit tests that lock down the behavior matrices

## Behavior invariants

Stage B preserves existing behavior:

- Engine decisions only control **which side effects happen**, not the side effects themselves.
- Ordering constraints remain unchanged (e.g. fixed destination handling still precedes duplicate filtering).
- For every `LinkHandleResult` / state combination, transport must perform the same side effects as before.

## Definition of done (Stage B)

Stage B is complete when all of these are true:

- The primary “follow-up mapping” matches in `transport.rs` are replaced by engine action decisions.
- The engine contains focused unit tests for the extracted decision functions.
- No behavior changes to the protocol rules (validated by running existing checks/tests).
- `cargo test transport::engine --no-default-features --features std` passes.
- `cargo check --no-default-features --features alloc` passes.

## Progress checkpoint

Stage B progress (current working state):

- Added engine decisions for:
  - `LinkHandleResult` follow-up mapping (`decide_link_handle_followup`)
  - `Link-table` proof follow-up mapping (`decide_proof_handle_followup`)
  - In-link pending-proof gating predicate (`should_consider_in_link_pending_proof`)
  - Old announce retransmit timing check (`decide_old_announce_retransmit`)
- `transport.rs` now uses those decisions and only performs runtime execution (locks, packet creation/sending).
- Verified with:
  - `cargo test transport::engine --no-default-features --features std`
  - `cargo check --no-default-features --features alloc`

## Follow-up stages (preview)

- **Stage C**: introduce adapter boundaries for runtime-bound operations (send, timers, tasks) so Embassy can plug in cleanly.
- **Stage D**: implement the Embassy driver using the protocol/engine seam.

