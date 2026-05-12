# Stage E: Embedded Messaging and Route-State Parity

## Goal

Move from Stage D runtime proof to usable embedded messaging behavior:

- real message send/receive flow on boards
- route/path state handling closer to std baseline
- keep one shared protocol decision core (no policy fork)

Stage E is where embedded stops being mainly "transport seam validation" and
starts acting like a practical Reticulum messaging runtime.

## Why this matters

Stage D proved:

- embedded runtime can execute shared policy decisions
- announce -> path-request behavior works on real boards
- basic lifecycle paths can be exercised safely

What Stage D did not fully deliver:

- user-visible messaging flow
- full route table parity with std transport state

Stage E closes that gap.

## Non-goals for Stage E

- No full feature-complete parity with all std transport features in one step.
- No broad performance tuning campaign.
- No major architecture rewrite; keep refactor-first and std as baseline.

## User-visible outcome target

At the end of Stage E, a user should be able to:

1. bring up two embedded nodes,
2. see discovery/path setup,
3. send at least one real application message from node A to node B,
4. observe successful receipt/handling (and optionally response) on node B.

## Scope

Stage E focuses on:

- embedded path/route state handling needed for messaging
- minimal real message flow using existing `minimal-embassy` harness
- preserving shared engine decisions as source of truth

## Files expected to change

- `src/transport_embedded.rs`
  - replace staged approximations with fuller std-like state handling where needed
- `src/transport_engine.rs`
  - only small shared helper moves when needed (policy extraction, no behavior fork)
- `minimal-embassy/src/main.rs`
  - add minimal message test flow on top of current harness
- `minimal-embassy/src/halow.rs`
  - keep UART framing stable enough for repeated message exchange
- `docs/embedded-runbook.md`
  - add Stage E message test procedure and expected signatures

## Milestone plan

### E1: Route-state parity for message path

- ensure embedded has the state inputs needed for message forwarding decisions
- reduce remaining "temporary cache only" behavior where it blocks real messaging

### E2: Minimal real message flow on boards

- implement one simple message send/receive scenario in `minimal-embassy`
- keep traffic low and logs explicit for pass/fail interpretation

### E3: Two-node stability for repeated messaging

- run repeated short message exchanges
- verify no panic loops and no persistent asymmetric behavior

### E4: Document and lock baseline

- document exact test steps and expected logs/counters
- capture known limits to defer to later stage

## Behavior invariants

Stage E must preserve:

- No protocol-policy fork between std and embedded.
- Shared engine decisions remain canonical.
- Runtime adapter executes decisions; it does not redefine policy.
- std behavior remains baseline reference for embedded parity.

## Definition of done (Stage E)

Stage E is complete when all are true:

- embedded build/flash path remains stable via `minimal-embassy`
- two-node embedded test demonstrates repeated real message exchange
- route/path state behavior needed by that flow is no longer purely staged approximation
- no new policy fork introduced
- runbook includes reproducible Stage E message test steps and expected logs

## Verification checklist

- Build checks:
  - `minimal-embassy` target builds and flashes on both boards
  - root no-std check remains green (`alloc` scope)
- Runtime checks:
  - repeated message send/receive succeeds in test window
  - no panic/reboot loops
  - no sustained framing collapse preventing messaging
- Regression checks:
  - std host checks still pass
  - shared engine tests still pass

## Current status

Stage E status: in progress (E2/E3 exercised on hardware; E4 baseline notes below).

Stage D output feeding Stage E:

- real board proof for announce -> path-request is established
- embedded and std share most Stage D policy decisions
- harness stabilization work reduced asymmetry enough to begin messaging tests

Stage E progress snapshot:

- `minimal-embassy/src/main.rs` now includes a low-rate Stage E message flow toggle
  that emits explicit `Data` payloads over the existing embedded egress path.
- HaLow receive handling now recognizes Stage E message payload markers and logs
  explicit message receive signatures for board pass/fail interpretation.
- Stage E message payloads are now fed back into `EmbeddedTransport` ingress
  classification/state counters via runtime-payload injection helpers.
- `src/transport_embedded.rs` now provides byte-slice ingress injection helpers:
  - `inject_ingress_packet_bytes(...)`
  - `inject_ingress_packet_from_interface_bytes(...)`

Known limits in this initial slice:

- Message flow currently uses prefixed payload markers (`stage-e-msg:`), not yet
  full protocol-level destination/link message semantics.
- Source attribution for injected message ingress uses latest verified peer
  observation from the harness and should be treated as a Stage E approximation.

Further progress (E1/E2):

- Stage E periodic TX now **unicasts to the last verified peer** (real A→B-style
  destination addressing). TX is skipped until a peer beacon has been decoded.
- Embedded runner applies shared **`decide_single_data_route`** on non-path-request
  `Data` ingress: counters `data_deliver_local_count` / `data_forward_candidate_count`
  and `EmbeddedEvent::DataRouted` mirror std’s local vs forward classification input.
- Embedded **`LinkRequest`** handling now uses shared **`decide_link_request_route`** (same
  local / intermediate / drop-unknown split as std) and
  **`link_request_destination_requests_proof`** for the lifecycle proof flag (aligned with
  `SingleInputDestination::handle_packet` when no destination object exists on device).

### E3 / E4: two-node check (observed pass criteria)

On two ESP32-S3 + T-HaLow boards running `minimal-embassy` (see `docs/embedded-runbook.md`):

- Each side prints **`Local Reticulum address hash:`** and later **`Peer Reticulum address hash:`** for the other node (reciprocal discovery).
- **`StageE message TX queued dest=<peer>/`** appears only after peer discovery; destination is the peer hash, not self.
- **`StageE message RX`** (and status **`data_local=`**) confirms the peer’s rotating `stage-e-msg:…` payloads are received and classified as local delivery.
- **`egress_dropped`** / **`event_dropped`** stay stable (no runaway growth) during a short soak.

Non-fatal observations to treat as environmental, not automatic regressions: occasional
**`SHA-256 comparison failed`** at boot with “Attempting to boot anyway”, **`rx_buf`** backlog,
or **`HaLow beacon TX forced after … RX-busy deferrals`** under heavy UART/RF activity.

### Next small steps (remaining Stage E scope)

- Optional application-level handling when local `Data` is classified as `DeliverLocal` (`EmbeddedEvent::DataRouted`).
- Closer alignment of ingress **`source_address`** with real per-packet origin where the radio path allows.
- Full Reticulum link/destination messaging semantics (beyond `stage-e-msg:` markers) as a later milestone.

## Stage E kickoff checklist (new agent)

Use this checklist as the first concrete implementation plan.

1. Route-state gap audit (`src/transport_embedded.rs`)
   - identify state currently approximated/staged that is required for real
     message forwarding/handling in Stage E.
   - map each gap to equivalent std baseline behavior in `src/transport.rs`.

2. Minimal message flow wiring (`minimal-embassy/src/main.rs`)
   - add a controlled low-rate message scenario on top of existing harness
     (node A send -> node B receive, optional response).
   - keep toggles simple so board pass/fail is obvious from logs.

3. Shared-policy reuse check (`src/transport_engine.rs`)
   - if a deterministic branch is still embedded-local but also present in std,
     move it to shared helper(s) first.
   - avoid introducing embedded-only policy variants.

4. UART/framing stability guard (`minimal-embassy/src/halow.rs`)
   - ensure message-flow test is resilient to expected UART chatter/noise patterns
     already documented in Stage D run behavior.

5. Validation and documentation (`docs/embedded-runbook.md`)
   - add exact Stage E board test command + expected message-flow log signatures.
   - list known limits explicitly so future agents do not treat them as regressions.

