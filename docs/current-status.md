# Current Project Status (Agent Handoff)

## Purpose

This document is the single handoff snapshot for a new agent joining this
repository. It summarizes what is complete, what is in progress, and what to do
next without re-reading every stage document first.

## Architecture baseline (must preserve)

- `std` transport behavior is the baseline reference.
- Shared protocol decisions live in `src/transport_engine.rs`.
- Runtime-specific execution stays in adapters/runners (`src/transport.rs`,
  `src/transport_embedded.rs`, `minimal-embassy/*`).
- No protocol-policy fork between std and embedded paths.

## Stage status

- Stage A (`docs/stage-a-transport-engine.md`): complete.
- Stage B (`docs/stage-b-transport-engine.md`): complete enough for Stage D/E
  work; remaining polish can be batched later.
- Stage C (`docs/stage-c-async-backend.md`): seam established and in active use.
- Stage D (`docs/stage-d-embedded-runtime.md`): complete for its scoped goals
  (embedded runtime execution proof on real boards).
- Stage E (`docs/stage-e-embedded-messaging.md`): current active stage.

## What Stage D proved

- Real-board `announce -> path-request` flow is working through the embedded seam.
- Basic link lifecycle signaling path is exercised.
- Shared policy helpers are used by both std and embedded in key ingress/action
  decisions.
- `minimal-embassy` harness was stabilized enough for iterative Stage E work.

## What is intentionally not done yet

- Full execution-path reuse from std `transport.rs` in embedded runtime.
- Full route-table/state parity for all messaging scenarios.
- Complete end-to-end embedded messaging feature coverage.

## Stage E immediate focus

1. Implement minimal real message send/receive on two embedded nodes.
2. Close route/path state gaps that block that flow.
3. Keep policy extraction shared; avoid adding embedded-only policy branching.
4. Update runbook with reproducible Stage E message test steps.

## Guardrails for new agents

- Prefer refactor-first changes over new features.
- When in doubt, mirror std behavior and move policy to shared engine helpers.
- Keep `minimal-embassy` as the board-proof harness for embedded validation.
- Avoid broad logging/observability expansion unless needed to unblock stage DoD.

## Suggested start sequence for a new agent

1. Read this file.
2. Read `docs/stage-e-embedded-messaging.md`.
3. Read `docs/embedded-runbook.md` for current board commands/checks.
4. Inspect `src/transport_embedded.rs` for remaining staged approximations.
5. Implement the smallest Stage E message-flow slice first, then validate on
   `minimal-embassy`.

