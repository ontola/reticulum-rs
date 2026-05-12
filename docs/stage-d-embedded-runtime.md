# Stage D: Embedded Runtime Execution (Embassy)

## Goal

Run a minimal but real Reticulum transport execution path on embedded
(`no_std`/Embassy), while reusing the same Stage A/B protocol decision logic
and the Stage C async-backend seam.

This stage proves that embedded execution can use the shared protocol core
without creating a forked implementation.

## Why this matters

- Stage A/B extracted deterministic protocol decisions into engine-style pure logic.
- Stage C introduced async backend seams so runtime primitives can be swapped.
- Stage D is where those seams are exercised on real embedded runtime execution.

Without Stage D, we only know that:
- the architecture is prepared, and
- HaLow beacon bring-up works.

With Stage D, we prove that protocol decisions and runtime execution connect
correctly on embedded.

## Non-goals for Stage D

- No full std/Tokio feature parity yet.
- No broad rewrite of every interface implementation.
- No large-scale performance tuning pass.
- No attempt to ship full Reticulum production behavior in this stage.

## Design seam for this stage

As in earlier stages, keep a strict separation:

1. **Decision (pure, shared)**
   - Engine decisions remain runtime-agnostic and unchanged.
   - Same policy behavior as std path.

2. **Execution (runtime-specific)**
   - Embassy tasks/timers/channels/mutexes execute chosen actions.
   - HaLow interface provides packet ingress/egress on embedded.

Stage D focuses on proving this bridge works.

## Scope (minimal executable slice)

Implement a minimal embedded transport runner that supports:

- ingress packet delivery into transport execution
- announce handling
- path request path (basic)
- basic link lifecycle path (request/proof activation path only)

This is enough to validate architecture and execution flow without requiring
full transport completeness.

## Hardware test harness (important)

Stage D hardware validation is run from `minimal-embassy/`.

- The communication and board wiring in `minimal-embassy/src/main.rs` and
  `minimal-embassy/src/halow.rs` is the baseline harness.
- New board tests (for example `announce -> path request`) should be built on
  top of this harness, not as a separate parallel setup.
- Shared `src/` changes should stay laptop-testable, but board-proof behavior
  must always be observable through `minimal-embassy` logs/counters/events.

## Files expected to change

- `src/async_backend.rs`
  - Fill/complete embedded-side runtime primitives used by transport path.
- `src/transport.rs`
  - Remove remaining std runtime assumptions from selected execution path.
- `src/iface_messages.rs`
  - Ensure embedded-safe message boundary types are sufficient for runner wiring.
- `minimal-embassy/src/main.rs`
  - Wire embedded runner task(s) to HaLow ingress/egress.
- `minimal-embassy/src/halow.rs`
  - Keep framing path stable for packet ingress/egress during Stage D tests.
- `docs/embedded-runbook.md`
  - Add Stage D run/verify section.

## Milestone plan

### D1: Backend completeness for selected execution path

- Identify the exact async primitives needed by selected transport path.
- Implement Embassy equivalents in `async_backend` for those primitives.
- Keep API shape close to existing std backend to minimize branch divergence.

### D2: Minimal embedded runner wiring

- Create a transport runner task that consumes ingress messages and executes
  action side effects using embedded backend primitives.
- Bridge HaLow RX -> ingress messages and transport egress -> HaLow TX.

### D3: Two-node protocol-path validation

On two ESP32-S3 + T-HaLow nodes:

- confirm repeated announce observation
- confirm path request path is executed
- confirm link request/proof path runs without stalls/panics

### D4: Stabilize and document

- Keep strict verification-first defaults.
- Keep diagnostic toggles available but disabled by default.
- Document known limits and what is intentionally deferred to later stage.

## Behavior invariants

Stage D must preserve these invariants:

- No protocol-policy fork between std and embedded paths.
- Engine decisions remain the source of truth for deterministic behavior.
- Runtime layer executes decisions; it does not redefine policy.
- Embedded defaults stay safety-first (verified paths preferred).

## Definition of done (Stage D)

Stage D is complete when all of these are true:

- `cargo check --no-default-features --features alloc,embedded` succeeds
  (for intended modules/targets in this stage scope).
- Embedded runner path compiles and flashes via `minimal-embassy`.
- Two-node hardware validation shows stable protocol-path execution for the
  scoped flows (announce, path request, basic link lifecycle).
- No new protocol behavior fork introduced in embedded path.
- Runbook documents exact commands, expected log signatures, and known limits.

## Verification checklist

- Build checks:
  - root crate (embedded/alloc scope)
  - `minimal-embassy` HaLow target
- Runtime checks:
  - no panic loops
  - no sustained RX framing collapse
  - repeated verified peer/protocol events in test window
- Regression checks:
  - std host examples still compile
  - Stage A/B engine tests still pass

## Progress checkpoint (current)

Current Stage D status: complete (scoped Stage D goals met).

Board evidence summary:

- two-node runs in `minimal-embassy` established stable `announce -> path-request`
  behavior under the Stage D harness setup.
- staged basic lifecycle coverage was observed without sustained panic/reboot loops.
- harness stabilization reduced persistent asymmetry enough to proceed to Stage E.

Implemented so far:

- Embedded runner seam exists in `src/transport_embedded.rs` (no Tokio dependency).
- Shared decision engine module is now available at `src/transport_engine.rs`
  and consumed by both std transport and the Stage D embedded seam.
- Shared module now also owns selected routing decisions
  (`decide_link_request_route`, `decide_single_data_route`,
  `decide_fixed_destination_route`) to further reduce std/embedded drift.
- Shared module now also owns link-request execution-intent helpers
  (`InLinkRegistrationAction`, `decide_in_link_registration_action`,
  `IntermediateLinkRequestAction`, `decide_intermediate_link_request_action`)
  so these no longer live only in the std compatibility layer.
- Shared module also owns path-request routing policy
  (`is_circular_path_request`, `decide_path_request_route`).
- Shared module now also owns duplicate/announce/keepalive ingress policy helpers:
  - duplicate gates/outcomes (`allow_duplicate_packet`, `duplicate_outcome`,
    `should_consider_in_link_pending_proof`)
  - announce route decisions (`decide_announce_discovery_route`,
    `decide_announce_retransmit_action`)
  - keepalive response gate (`should_handle_keepalive_response`)
- Shared module now also owns:
  - keepalive byte classification (`KeepAliveKind`, `classify_keepalive_byte`)
  - old-announce retransmit timing policy (`decide_old_announce_retransmit`)
- Shared module now also owns link/proof follow-up decisions:
  - `decide_link_destination_data_route`
  - `decide_proof_link_followup`
  - `decide_proof_handle_followup`
- Shared module now also provides std-gated link packet follow-up policy:
  - `LinkHandleFollowup`
  - `decide_link_handle_followup`
- `src/transport/engine.rs` now acts as a compatibility layer for migrated decisions
  (re-exporting shared `transport_engine` policy), while retaining the still-local
  link maintenance/intermediate route helpers.
- Runner wiring is active in `minimal-embassy/src/main.rs` (HaLow path).
- Embedded async backend now includes a Stage D `mpsc` adapter in `src/async_backend.rs`
  to reduce std/embedded call-site divergence for queue-style flows.
- Typed Stage D commands/events are present:
  - commands: probe/synthetic packet emission and runtime toggles
  - events: ingress classification, egress generation, lifecycle transitions
- Added explicit synthetic ingress injection helper in the Stage D seam:
  - `EmbeddedTransport::inject_ingress_packet(...)` lets us exercise Data/Path/Link/Proof
    classification and lifecycle transitions without depending only on live RF timing.
- `minimal-embassy` now has Stage D runtime toggles:
  - `STAGE_D_ENABLE_PERIODIC_SYNTHETIC_TRAFFIC`: enables/disables periodic synthetic
    ingress+egress stimulation used for seam validation.
  - `STAGE_D_ENABLE_AUTO_PROBE_ON_ANNOUNCE`: enables/disables automatic probe generation
    when announce ingress is observed.
- Shared Stage D path-request classification now lives in `src/transport_engine.rs`
  (`is_path_request_packet`, `STAGE_D_SYNTH_PATH_REQUEST_PAYLOAD`) and is used by both:
  - std transport fixed-destination path-request gate
  - Stage D embedded runner ingress counters/classification
- Stage D announce auto-probe now emits a staged path-request-shaped packet
  (`Data` + `Request` context + shared synthetic marker payload) to validate
  announce -> path request emission path in embedded runs.
- Embedded ingress policy inputs are now partially wired in `transport_embedded`:
  - fixed-destination path-request detection uses shared `path_request_fixed_destination()`
  - fixed-destination path-request handling now uses shared gate
    `should_handle_fixed_destination_path_request(...)` (same gate used by std transport)
  - duplicate filtering uses packet hashes + shared duplicate-policy helpers
  - duplicate outcome composition now uses shared helper
    `decide_duplicate_outcome(...)` in both std transport and Stage D embedded runner
  - ingress decision from duplicate outcome now uses shared helper
    `decide_ingress_from_duplicate_outcome(...)` in both std and embedded paths
  - shared in-link pending-proof helper `is_in_link_pending_proof(...)` is now used
    in both std transport and Stage D embedded runner
- Shared path-request execution-intent helper now exists in `src/transport_engine.rs`:
  - `PathRequestExecutionIntent`
  - `decide_path_request_execution_intent(...)`
  and is now used by std `handle_path_request(...)` and the Stage D embedded
  announce-triggered path-request emission gate.
- Shared path-request action helper now exists in `src/transport_engine.rs`:
  - `PathRequestAction`
  - `decide_path_request_action(...)`
  and is now used by std `handle_path_request(...)` so route->action mapping
  lives in shared policy code rather than local std branching.
- Shared path-request state-input helper now exists in `src/transport_engine.rs`:
  - `decide_path_request_action_from_state(...)`
  and is now used by:
  - std `handle_path_request(...)` (uses real requesting transport + path-table source)
  - Stage D embedded announce-triggered path-request gate
- Stage D embedded runner now tracks a small destination->received_from cache
  (`EmbeddedTransportConfig::path_state_cache_size`) so path-request state input
  to shared helpers is no longer always `None/None`.
- Stage D embedded runner now also tracks a small destination->known_hops cache
  (`EmbeddedTransportConfig::known_hops_cache_size`) and feeds those observations
  into shared `decide_path_request_action_from_state(...)` input.
- Stage D embedded runner now has `EmbeddedTransportConfig::retransmit_enabled`
  so the shared path-request action helper can follow the same retransmit gate
  shape as std policy (currently `false` by default in Stage D harness).
- Shared normalized ingress/path input shapes now exist in `src/transport_engine.rs`:
  - `IngressDecisionInput` + `decide_ingress_from_input(...)`
  - `PathRequestDecisionInput` + `decide_path_request_action_from_input(...)`
  - `PathRequestStateObservation` + `lookup_path_request_state(...)`
  - `build_path_request_decision_input(...)`
  and both std/embedded paths now use those normalized helpers to reduce
  per-runtime input-shaping drift.
- Stage D embedded runner now also applies shared path-request action decision
  in the `Data` ingress path when packets classify as path-request-like, not
  only in announce-triggered staged emission.
  - fixed-destination path-request ingress now also executes the same shared
    path-request decision/action route in embedded (instead of count-only),
    improving behavioral alignment with std `handle_fixed_destinations -> handle_path_request`
  - announce/data/fixed-destination path-request handling now goes through one
    local Stage D execution helper closure (`execute_path_request_for_current_packet`)
    to reduce per-branch drift in embedded runner glue
  - recursive staged-egress eligibility now uses shared helper
    (`recursive_broadcast_exclude_iface`) from `transport_engine`, so embedded
    no longer duplicates the action-variant policy match locally
  - staged action->egress decision now also uses shared helper
    (`decide_staged_path_request_egress`) from `transport_engine`
    (`EmitRecursive` / `CountOnly` / `None`), further reducing embedded-local
    action branching
  - rebroadcast input is now configurable via `EmbeddedTransportConfig::broadcast_enabled`
  - duplicate cache size is configurable via `EmbeddedTransportConfig::duplicate_cache_size`
- Stage D counters/logging now include:
  - ingress source split: `interface_ingress`, `synthetic_ingress`
  - `announce`, `data`, `path_req`, `link_request`, `proof`
  - `pending`, `activated`, `egress_generated`
  - backpressure observability: `egress_dropped`, `event_dropped`
- Runtime status logs now emit a `StageD pressure warning` line whenever drop counters
  increase between status intervals.
- `minimal-embassy` now applies synthetic-traffic cooldown after pressure warnings
  (temporary backoff) to avoid compounding queue overload during Stage D seam runs.
- Synthetic Stage D pacing is now adaptive:
  - repeated pressure increases synthetic interval (less stimulation),
  - clean intervals gradually relax back toward normal pacing.
- `EmbeddedEvent::IngressClassified` now includes ingress source metadata
  (`Interface` vs `Synthetic`) for easier log interpretation during mixed runs.
- Basic link-lifecycle signal path is exercised in the seam:
  - `LinkRequest` observed -> pending
  - `Proof` observed -> activated
  - shared link lifecycle transition helper now exists in `transport_engine`:
    `decide_link_lifecycle_transition(...)` with
    `LinkLifecycleTransition::{AddPending, Activate, None}`
    and is used by Stage D embedded link-request/proof ingress handling
    and now also by std link-request destination/proof follow-up handling
    (single shared decision entrypoint for both runtimes)
  - `LinkRequest` pending-transition gate now uses shared
    `decide_in_link_registration_action(...)` policy helper in Stage D embedded
    (with current seam approximation for "requested proof" input), reducing
    embedded-local decision branching for link ingress
  - `Proof` activation follow-up gate now uses shared
    `decide_proof_link_followup(...)` policy helper in Stage D embedded, reducing
    embedded-local proof follow-up branching
  - embedded ingress execution now uses one local transition-execution helper
    for link lifecycle side effects (`pending` / `activated`) after shared
    lifecycle decisions, reducing branch-local side-effect duplication
- Root no-std compile gate currently used for this stage:
  - `cargo check --no-default-features --features alloc`

Known Stage D `mpsc` adapter limits (documented intentionally):

- Capacity parameter is currently fixed internally (`DEFAULT_CAPACITY`).
- Receiver close semantics are not fully modeled yet (current setup keeps channel alive).
- Error types are compatibility wrappers, not full Tokio-equivalent enums.

Known Stage D channel behavior limits:

- `broadcast`/`mpsc` adapters are currently bounded and non-blocking in key send paths.
- Under burst load, non-critical observability channels may drop messages.
- Stage D now tracks those drops explicitly (`egress_dropped_count`, `event_dropped_count`)
  so runs can detect and discuss pressure instead of silently losing signals.

Intentionally deferred beyond Stage D:

- Full transport execution reuse from `src/transport.rs` on embedded
  (current path is still a staged runner seam, but ingress classification now
  already uses shared `decide_ingress` policy).
- End-to-end embedded validation of full path request and real link activation
  using shared transport execution (beyond staged synthetic signaling).

## Exit criteria for moving to next stage

Move beyond Stage D only after:

- embedded execution path is stable enough for iterative feature work, and
- diagnostics indicate failures are edge cases, not dominant behavior.

At that point, future work can focus on expanding feature coverage and reducing
remaining std-only execution assumptions.
