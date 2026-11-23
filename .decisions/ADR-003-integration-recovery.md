# ADR-003: Repository strategy and integration recovery

- Status: Accepted
- Date: 2026-11-23

## Context

All roadmap and gate issues were closed, but the shipped gateway does not enforce the product. The
bootable server attaches the management endpoints and answers every other path with a static banner.
The core proxy, identity, policy, anomaly, DLP, approval, and validation stack is assembled only inside
the end-to-end fixture. The live inspector event stream is not implemented, management endpoints
authenticate with token-substring heuristics, and the console falls back to simulated data. Four tests
fail: the proxy latency benchmark, the one-megabyte DLP scrub, a platform-specific `npm` invocation,
and a CLI usage assertion corrupted by ANSI escapes.

Three paths were considered:

1. Archive the repository and reimplement from the specification.
2. Keep the repository, re-scaffold the coordination layer, and add an integration recovery phase.
3. Create a new repository and port the tested modules.

Path 1 discards roughly eleven thousand lines of tested security logic and repeats the process that
produced the gap. Path 3 preserves the code but loses history and issue provenance. Path 2 keeps the
tested libraries, the specification submodule, and the historical record while changing the gates that
failed.

## Decision

Adopt path 2.

- The repository stays at `aegismcp` with `docs` as the `aegismcp-docs` submodule.
- The coordination layer is re-scaffolded with `vanguard-scaffold`: root `AGENTS.md`, the docs router,
  the area manuals, `contracts/`, `assets/ASSETS.md`, the issue and pull-request templates, and the
  decision record.
- Interfaces live in `contracts/`, one file per contract (`contracts/C-###.md`), indexed by
  `contracts/README.md`. The monolithic `CONTRACTS.md` is deleted. Contract v2 applies: a contract moves
  `Draft` to `Frozen` when both sides agree, and to `Implemented` only when a conformance test passes
  against the packaged artifact in CI.
- The end-to-end harness becomes artifact-first. It launches the packaged gateway and never composes
  gateway handlers or Netty pipelines. It may provide only mock upstream servers, identity material,
  and test data.
- `AegisGatewayServer` is the single composition root. A production class reachable only from tests is
  a defect, and every capability ships with an artifact-level boot test.
- Integration recovery is added to the roadmap as Phase 4, after the current feature phases, and is
  gated like any other phase.
- Phase 0 gains a boot check that exercises the packaged artifact, and CI runs the gateway, CLI,
  console, and artifact suites as required jobs.
- Performance requirements are fixed, not relaxed. The latency benchmarks measure added latency
  against a direct-upstream baseline on a pinned runner.

Existing closed issues remain closed as the historical record. New issues reference the issue they
supersede rather than reopening work under a claim that was never true.

## Consequences

- The tested libraries (policy, DLP, anomaly, audit, compliance, identity, validation, CLI, console)
  are retained; the missing work is assembly, transport coverage, identity enforcement, configuration,
  and the console-to-gateway boundary.
- No feature phase is considered done until its contracts are implemented against the artifact and its
  conformance tests pass in CI.
- A phase gate may now fail for a reason that was previously invisible: the artifact does not run what
  the unit suite tested.
