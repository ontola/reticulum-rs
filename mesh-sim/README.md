# reticulum-mesh-sim

Host-side mesh simulator for `reticulum-rs`.

This crate exercises Reticulum-style packet behavior with many virtual nodes in one process so you can test routing, forwarding, mobility, and congestion without a physical WiFi HaLow lab for every scenario.

Long term it should wrap `EmbeddedTransport` and drive the real Embassy-oriented transport path. **Today** it simulates at the **packet boundary** (`Packet`, announce/data flows, distance-based “air”, and bounded queues) so we can already stress **node count**, **memory limits**, and **processing budget** and read **stability metrics**.

## Quick start

From the workspace root:

```sh
cargo test -p reticulum-mesh-sim
cargo run -p reticulum-mesh-sim
cargo run -p reticulum-mesh-sim -- --help
```

Criterion timing (add `-- --quick` for a short run):

```sh
cargo bench -p reticulum-mesh-sim --bench mesh_stress
```

### CLI (current)

The binary runs a **line topology** announce workload using `run_line_announce_benchmark` and prints traffic, drops, queue peaks, and [`StabilityMetrics`](src/lib.rs).

```text
cargo run -p reticulum-mesh-sim -- \
  --nodes 64 \
  --ticks 128 \
  --spacing 1.0 \
  --range 1000 \
  --air-queue 256 \
  --inbox 16 \
  --routes 64 \
  --ppt 4 \
  --announce 1 \
  --latency 1
```

See `cargo run -p reticulum-mesh-sim -- --help` for the full flag list.

### Library: benchmarks and stability

Use these types for programmatic sweeps (see `src/lib.rs`):

| Type | Role |
|------|------|
| `BenchmarkParams` | `nodes`, `ticks`, `radio_range`, `spacing`, plus nested budgets |
| `MeshMemoryBudget` | `inbox_limit`, `route_table_limit`, `air_queue_limit` |
| `MeshBandwidthBudget` | `packets_per_tick`, `latency_ticks`, `announce_interval` |
| `run_line_announce_benchmark` | Builds the line mesh, runs ticks, returns `BenchmarkReport` |
| `StabilityMetrics` | `drops_per_tick`, `resource_drops_per_tick`, `air_tx_success_ratio`, `avg_route_table_utilization`, etc. |
| `SimStats` | Counters including `air_tx_attempts` / `air_tx_ok` for air-queue success ratio |

`resource_drops_per_tick` aggregates **air queue full**, **inbox full**, and **route table full** drops—useful when varying buffers and node count.

## Goals

- Run hundreds to thousands of Reticulum-like nodes in one process.
- Use the same embedded transport path used by Embassy/HaLow work (`reticulum::transport_embedded`) once the simulator wires through it.
- Keep simulator behavior outside the core protocol implementation.
- Model physical-world movement: nodes can move, lose links, regain links, and form transient clusters.
- Model unreliable radio behavior: packet loss, high latency, jitter, duplicates, asymmetric links, and bandwidth constraints.
- Model operational failures: dead batteries, dropped connections, rebooting nodes, and overloaded relays.
- Model adversarial behavior: spammy announces, data floods, replays, and selective forwarding.
- Produce deterministic regression tests for small topologies and reproducible seeded simulations for large scenarios.

## Non-Goals

- Do not reimplement Reticulum routing policy inside the simulator.
- Do not put simulator-specific behavior into `src/transport.rs`, `src/transport_embedded.rs`, or `src/iface.rs` unless it is a small generic boundary that real transports can also use.
- Do not use OS sockets per simulated node.
- Do not spawn one OS thread per node.
- Do not make the simulator depend on real WiFi/HaLow hardware.

## Relationship To The Main Crate

The simulator is a separate workspace crate so it can grow without turning the core library into a simulation framework.

Core crate responsibilities:

- `transport_engine`: runtime-independent protocol decisions.
- `transport_embedded`: Embassy-oriented transport runner and packet ingress/egress boundary.
- `iface`: real std interfaces such as TCP, UDP, HDLC, and Kaonic.

Simulator crate responsibilities:

- virtual nodes,
- virtual interfaces,
- virtual air/radio medium,
- movement/topology models,
- loss/latency/interference models,
- adversary models,
- metrics and scenario runners.

The simulator should interact with Reticulum through public boundaries such as:

- `EmbeddedTransport`,
- `EmbeddedTransportPort`,
- `RxMessage`,
- `TxMessage`,
- `TxMessageType`,
- `EmbeddedTransportStats`.

It should not call low-level policy helpers directly in normal simulation flows. Those helpers are for transport implementation and focused unit tests.

## Architecture (target)

```text
Scenario
  |
  v
Simulation
  |
  +-- NodeRegistry
  |     +-- SimNode { EmbeddedTransport, position, radio state, behavior }
  |
  +-- VirtualAir
  |     +-- topology lookup
  |     +-- mobility updates
  |     +-- impairment pipeline
  |     +-- packet dispatch
  |
  +-- Metrics
        +-- delivered/dropped/forwarded packets
        +-- convergence timing
        +-- route churn
        +-- per-node health
```

**Current code** implements `MeshSim` with `SimNode`, a shared scheduled “air” queue, distance-based links, and stats compatible with benchmark reporting—the diagram above remains the target shape once nodes own `EmbeddedTransport`.

## SimNode (target)

A simulated node should own one `EmbeddedTransport` instance and simulation state:

- stable node ID,
- one or more virtual interface addresses,
- physical position,
- velocity or mobility script,
- online/offline state,
- battery/power state when relevant,
- application behavior, such as periodic announces or data sends,
- optional adversarial behavior.

Normal nodes should send packets only through their transport egress path and receive packets only through transport ingress injection.

## VirtualAir (target)

`VirtualAir` is the in-process radio medium. It receives egress packets from nodes and decides which other nodes hear them.

It applies:

- range checks,
- topology rules,
- link state,
- packet loss,
- latency and jitter,
- bandwidth limits,
- interference,
- node offline/dropout state,
- malicious traffic rules where configured.

The first implementation can be simple full-mesh dispatch. The target design should support dynamic topology where links change as nodes move.

## Topology And Mobility

Topology should be computed from physical state, not hard-coded into node logic.

Initial topology modes:

- `FullMesh`: every online node hears every other online node.
- `StaticGraph`: explicit adjacency list.
- `Distance`: nodes hear each other when distance is below a radio range. **Implemented** in `MeshSim`.
- `Partitioned`: groups can split and later merge.

Mobility modes:

- `Stationary`: fixed positions.
- `Waypoint`: nodes follow scripted waypoints.
- `RandomWalk`: useful for stress tests.
- `TraceReplay`: later support for real GPS or scenario traces.

**Implemented:** stationary line layout in `run_line_announce_benchmark`, plus `MeshSim::set_position` for movement tests.

Dropout modes:

- scheduled offline/online intervals,
- probabilistic connection loss,
- low-power sleep periods,
- relay failure events.

**Implemented:** `MeshSim::set_online`.

## Impairments

Impairments should be composable and deterministic when given a seed.

Examples:

- fixed packet loss percentage,
- burst loss,
- per-link **latency in ticks**—**partially implemented** via `RadioConfig::latency_ticks` / `MeshBandwidthBudget::latency_ticks`,
- latency jitter,
- duplicate delivery,
- bandwidth queueing—**partially implemented** via `packets_per_tick`, air/inbox limits, and announce intervals,
- asymmetric receive quality,
- interference zones.

## Adversarial Nodes

Adversarial behavior should be isolated from normal node logic.

Examples:

- announce spammer,
- data flooder,
- replay sender,
- blackhole relay,
- selective forwarder,
- malformed packet source where packet construction is safe.

The simulator should be able to turn adversaries on and off during a run.

## Testing Strategy

Fast regression tests stay small (see `src/lib.rs` `mod tests`):

- two nodes learn routes from announces,
- three-node line forwards data,
- movement breaks and restores connectivity,
- dense announce pressure shows queue clogging,
- benchmark harness compares loose vs tight memory/bandwidth.

Large tests should be explicit and normally ignored:

```rust
#[ignore]
#[test]
fn thousand_node_mesh_runs_for_one_simulated_minute() {
    // scenario runner
}
```

## Milestones

Progress (rough):

1. Host-side packet-level simulator with distance topology, announces, data forward, queues, stats — **done** (`MeshSim`).
2. Line benchmark runner + stability metrics + Criterion bench — **done**.
3. CLI smoke runner — **done** (`src/main.rs`).
4. Move an existing two-node Embassy virtual test helper into this crate — **pending**.
5. `VirtualAir` as a composable module; `SimNode` wrapping `EmbeddedTransport` — **pending**.
6. Seeded packet loss and jitter; richer topologies — **pending**.
7. Config-file / scripted scenarios (TOML or similar) — **pending**.

## CLI direction (future)

```sh
cargo run -p reticulum-mesh-sim -- \
  --nodes 1000 \
  --topology distance \
  --range-meters 800 \
  --duration-seconds 300 \
  --loss 0.02 \
  --latency-ms 80 \
  --jitter-ms 30 \
  --dropout-script scenarios/relay-dropout.toml
```

The current binary is a subset of this (line topology, tick-based latency, no loss/jitter script yet). A concise summary + optional Prometheus export can come later.

## Design constraint

Simulator realism must not come from copying protocol logic. It must come from creating realistic packet delivery conditions around the real transport implementation.
