# tests/e2e

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside
`Own` is read-only. This area writes test sources and test configuration only: the suites under
`src/test/java`, the resources under `src/test/resources`, and this area's `build.gradle.kts`.
Production behavior in `services/gateway`, `apps/cli`, and `apps/console` is read-only.

## Structure

- `src/test/java/dev/aegismcp/e2e/` — phase journey suites, one class per roadmap phase gate
  (`Phase1...`, `Phase2...`, `Phase3...`), which walk a user flow end to end through the launched
  artifact, plus the cross-cutting latency benchmark class.
- `src/test/java/dev/aegismcp/e2e/contracts/` — the contract suite. One class per `C-###`,
  named `C###<Domain>ContractTest` (for example `C001RpcProxyContractTest`). Every new contract
  test goes here; a `C-###` with no class here is unverified.
- `src/test/java/dev/aegismcp/e2e/compliance/` — compliance and audit journeys that span
  several contracts: ledger verification, audit record queries, and signed report export.
- `src/test/java/dev/aegismcp/e2e/validation/` — argument validation, sanitization, and policy
  simulation behavior exercised through the public API.
- `src/test/java/dev/aegismcp/e2e/fixtures/` — harness plumbing: artifact launcher, readiness and
  port discovery, mock upstream MCP servers, identity material provisioning, and per-test seed and
  reset helpers. Fixtures may import no production handler, interceptor, cache, ledger, or pipeline
  type.
- `src/test/java/dev/aegismcp/e2e/generators/` — deterministic credential material: key pairs,
  certificates, JWTs, and JWKS documents used to seed identity fixtures. Generators hold no
  assertions and no process control.
- `src/test/resources/` — declarative policy files, seed payloads, and static TLS fixtures.
  Generated material and runtime state go to per-test temporary directories, never into the
  repository tree.
- Placement: a test targeting one contract goes in `contracts`; a test walking a cross-contract
  journey goes in the phase, compliance, or validation package. A helper used by one suite stays
  package-private beside it; a helper shared by two or more suites is promoted to `fixtures` or
  `generators`.
- `build.gradle.kts` is this area's manifest. The launch classpath, test framework, and every
  client dependency are declared there, never here.
- The existing helpers currently sit loose in the root package. `E2EMockMcpChildServer`,
  `E2EJwtGenerator`, and `E2ECertificateGenerator` belong in `fixtures`/`generators` as they are
  touched. `E2EGatewayFixture` is not relocated: it composes the gateway in-process and is
  replaced by the artifact launcher described under Discipline. Nothing new is added to the root
  package except phase journey suites and the benchmark.

## Task rules

- Work only inside the issue's `Own` paths; everything outside `Own` is read-only.
- Code tasks never write under `docs/`. A doc gap becomes a `doc-gap` issue.
- Commit only your owned paths. Conventional Commits linking spec and issue (e.g. `Implements: FEAT-###`, `Fixes #<n>`). Never `git add -A`.
- Branch from `main` with `<class>/<issue-number>-<slug>` (e.g. `implement/12-feat-001-auth`), open a PR, never push to `main`.
- In code and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, `EVT-###`, or `C-###`). Commits and PRs link the spec and the GitHub issue.
- Implement all states, schemas, and events assigned to your area; never leave stubbed states or skip declared non-happy paths.
- Never log or commit secrets, tokens, or unmasked identity; credentials live in the secret store.
- Document code inline with docstrings and comments on non-obvious logic; skip trivial comments. Never create ad-hoc markdown documentation files.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- Execute strictly against the assigned issue contract. Never modify files outside your owned paths. If feedback or findings uncover defects outside your scope, report back to the coordinator for triage rather than performing out-of-scope edits.
- Do not reinvent the wheel: prefer established, battle-tested ecosystem packages over bespoke implementations. Research standard libraries and agree with the user before adding or changing external dependencies.
- Packages and dependencies belong strictly in this area's manifest (build.gradle.kts), never in `AGENTS.md`.
- If blocked, state the assumption or ask for clarification before proceeding.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Discipline

1. **Artifact-first.** A suite launches the gateway launcher produced by the gateway module's
   distribution task, or its production main class in a child process, and reaches it only over
   HTTP or stdio on the routes an agent or console uses. Readiness comes from the artifact's own
   startup output; where the artifact binds a port, discover it from that output. Test sources
   never construct a server, handler, interceptor, codec, cache, ledger, or Netty pipeline, never
   add, replace, or reorder a pipeline handler, and never call a production method to seed or
   inspect state. The `E2EGatewayFixture` pattern — building `AegisGatewayServer`, chaining
   `ToolCallInterceptor`s, and injecting handlers into a `ChannelPipeline` from the test JVM — is
   prohibited and must not return under another name. Fixtures may provide only mock upstream MCP
   servers, identity material, and test data, and must configure the artifact through its
   documented environment variables or command-line surface. Mock upstream servers run as their
   own child processes or servers outside the gateway, never as in-process pipeline components.

2. **Contract-bound.** The contract files under `contracts/` are the oracle: read
   `contracts/C-###.md` for the entry under test, indexed by `contracts/README.md`. Each `C-###`
   has exactly one class under `dev.aegismcp.e2e.contracts` named `C###<Domain>ContractTest`, and
   that class covers the documented success response plus every error row listed for the entry:
   status code, JSON-RPC error code, and payload shape where the contract states one. An untested
   error row is a failing gate, not an optional case. A contract change updates its class in the
   same PR. Assert only what the contract states; a missing row is a change request, not an
   invented expectation.

3. **Honest NFR measurement.** Added latency is the proxy round-trip minus a direct-upstream
   baseline taken on the same host with the same payload and the same client configuration, after
   warm-up. Report added p50/p95/p99, the sample size, and every failing case. Thresholds, load
   assumptions, and percentiles come from the `NFR-###` row under test; the constant in the test
   names that row and carries no independent number. Never widen a threshold, shrink a sample,
   discard outliers, retry until green, or skip the benchmark to reach a gate. A host that cannot
   produce a valid baseline is a reported blocker, not a passing test.

4. **Portable process control.** Resolve platform executables explicitly — the `.bat`/`.cmd` shim
   on Windows, the POSIX script elsewhere — and pass arguments as a list, never as a shell string.
   Do not depend on shell built-ins, globbing, or `PATH` lookup for the artifact. Bound every wait
   — process start, readiness line, HTTP connect and read, first SSE event, approval polling, and
   shutdown — with an explicit timeout that fails the test with captured stdout and stderr. Drain
   stdout and stderr concurrently so a full pipe cannot deadlock the child. Tear down every
   process, server, temporary directory, and file handle in `@AfterEach` or try-with-resources,
   including when setup fails; terminate descendants and wait for exit before the next test.

5. **Hermetic and deterministic.** Each test allocates its own ephemeral port, starts from a fresh
   temporary state directory, seeds its own policy, identity, and data, and leaves no shared
   mutable fixture behind. No live network: upstream MCP servers, identity providers, and
   notification endpoints are local mocks. No static singleton or shared fixture carries state
   between classes, and test order must not matter. The suite passes from a clean checkout with no
   pre-existing build output, credentials, or running services. Assertions about time, identifiers,
   and ordering are range- or invariant-based unless the artifact exposes a deterministic seed.

6. **Verifier separation.** This area never fixes feature code, tunes a test to match an
   implementation, or edits a threshold. Report each failure with file/line, the request and
   response, and expected versus actual. A production defect goes back to the coordinator as a
   defect; a contract discrepancy becomes a change request; a requirement with no acceptance
   criterion becomes a `doc-gap` issue. Never disable or ignore a test to reach a green gate, and
   never invent a test for an unstated requirement.

## Checks

- Build launchable artifacts: `./gradlew :services:gateway:installDist :apps:cli:installDist`
- Run end-to-end suite: `./gradlew :tests:e2e:test`
- Run latency benchmark: `./gradlew :tests:e2e:test --tests "dev.aegismcp.e2e.Phase1PerformanceLatencyBenchmarkTest"`
- Clean-checkout run: `./gradlew clean :tests:e2e:test`

## Definition of Done

- The full suite passes from a clean checkout with launchable artifacts built.
- Every `C-###` in `contracts/` has a green `C###<Domain>ContractTest` covering its success path
  and all of its error rows.
- Every `NFR-###` measured here is reported with metric, sample size, and failing cases.
- No test constructs production internals, and no process, port, or temporary file outlives its test.
- Checks run cleanly with no disabled, ignored, skipped, or placeholder tests and no unresolved
  stubs or TODOs.
- Defects found are reported, not patched from this area.

## Report

Task and feature IDs and the phase gate; files changed; the `C-###` classes added or changed; test
results per suite; each `NFR-###` metric with sample size and failing cases; defects raised with
file/line and expected versus actual; contract change requests; blockers or environment
limitations; commands run.
