# services/gateway

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside `Own` is read-only.

## Structure

- Single Gradle module rooted at `services/gateway`; the build definition is `build.gradle.kts` and
  the application entry point is `dev.aegismcp.gateway.AegisGatewayServer`. There is no second
  module and no `api`/`impl` split: packages separate security responsibilities, not build units.
- `src/main/java/dev/aegismcp/gateway/` is the code root. `AegisGatewayServer` lives at its top level
  and is the composition root: it owns the Netty bootstrap, event-loop groups, the virtual-thread
  executor, the channel initializer, the handler order, lifecycle, and `main`. Nothing else binds a
  port or assembles the request path.
- `codec/` owns the JSON-RPC 2.0 model, framing decoders, encoders, and codec errors. It makes no
  authorization decision and writes no channel bytes itself.
- `proxy/` owns the HTTP entry handler, `SecurityContext`, the `ToolCallInterceptor` /
  `InterceptionVerdict` contract and its chaining, the upstream transport boundary, and the pipeline
  configurators. Interceptors are composed in the composition root; policy, anomaly, validation, and
  DLP logic stay in their own packages.
- `identity/` owns credential validation for SPIFFE X.509 SVIDs and OIDC bearer tokens, and resolution
  into the canonical `AgentIdentity`. It is the only package that decides whether a credential is
  authentic.
- `policy/` owns YAML compilation, the policy AST, the compiled-policy cache, the evaluator, the
  policy interceptor, and the policy management endpoints.
- `validation/` owns JSON-schema checking, injection and traversal detection, the tool schema
  registry, and the pre-execution validation interceptor.
- `dlp/` owns patterns, entropy scanning, the scrubber, the redaction engine, and the outbound
  response filter and its pipeline configurator.
- `anomaly/` owns session sequence tracking, transition and burst rules, the anomaly circuit breaker,
  violation records, alert dispatch, and the chaining interceptor.
- `approval/` owns the ticket lifecycle, the manager, decisions, and the approval management
  endpoints.
- `audit/` owns the hash chain, Merkle proofs, the append-only ledger, audit records, and the
  verification and records endpoints.
- `killswitch/` owns quarantine targets, the kill-switch manager, gateway metrics, the invocation
  velocity breaker, and the emergency, status, and metrics endpoints.
- `compliance/` owns report generation, attestation signing, and the export endpoint.
- Tests live under `src/test/java/dev/aegismcp/gateway/` and mirror the main package of the unit they
  exercise. `AegisGatewayServerTest` at the test root is the artifact boot test; a cross-package
  end-to-end test may sit beside the package it drives. Test-only helpers (`TestCertificateGenerator`,
  `TestJwtGenerator`) live beside the tests that use them and never in `src/main`.
- Resources: `src/main/resources` carries what ships inside the artifact (logging configuration,
  default policy documents, schema catalogs); `src/test/resources` carries fixtures only. Neither
  directory exists yet; when the first resource is needed, create it there rather than embedding the
  document as a string literal in code. Per-environment values are configuration, not resources.
- Placement rule: a new security capability is a new package under `gateway` named for the function it
  performs, entered through a `ToolCallInterceptor` or an HTTP handler and registered in
  `AegisGatewayServer`. A new endpoint is a `SimpleChannelInboundHandler<FullHttpRequest>` in the
  owning package with a path constant, attached in the channel initializer. Its interface is authored
  in `contracts/C-###.md`; the payload is a DTO in the owning package. A shared type used across
  packages (`SecurityContext`, `JsonRpcRequest`, `JsonRpcResponse`, `AgentIdentity`) has exactly one
  home; never redeclare it locally. Do not add a new top-level folder under `gateway` without updating
  this section.

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

- **One composition root.** `AegisGatewayServer` constructs or accepts every request-path collaborator
  and attaches every handler and interceptor in a single channel initializer; constructors may take
  collaborators for tests, but the shipped path has exactly one assembly. The interceptor order is
  declared once there, following the architecture's data flow: identity, parameter validation, policy
  (which may suspend for approval), anomaly, upstream, DLP on the response, audit for every terminal
  outcome. A new stage is inserted in that order and covered by the boot test. A request travels that
  chain until the handler that owns its path answers; no fallback may answer a contract path with a
  success body the gateway did not produce. A production class
  reachable only from a test is a defect: wire it into the shipped path or delete it. Every capability
  ships an artifact-level boot test that starts the real server on an ephemeral port and exercises the
  path it added, not unit tests of the class alone.
- **Verified identity at the edge.** Management, emergency, metrics, audit, and compliance endpoints
  authenticate through the frozen identity validators and the roles named by that endpoint's
  `contracts/C-###.md` entry; never a substring test on the token, never a caller-supplied identity
  header the gateway has not verified, never a role inferred from the token text. Distinguish
  unauthenticated from authenticated but unauthorized exactly as the contract specifies. Any identity,
  policy, approval, validation, or DLP error, denial, or timeout fails closed: no upstream call, no
  allow verdict, no partially applied decision, no silent fallback to an anonymous or default identity.
- **Nothing blocks the event loop.** Netty event-loop threads do framing and buffer ownership only.
  Disk writes, JWKS and IdP calls, upstream HTTP, webhook delivery, ledger flushing, Merkle and digest
  work, policy compilation, and pattern scanning over large payloads run on virtual threads or a
  dedicated worker, never inline on an event-loop thread; no `sync()`, `join()`, or `get()` there.
  Every retained `ByteBuf` is released on success, error, timeout, client disconnect, and cancellation,
  and every response write is scheduled on the channel's own executor.
- **Contract exactness.** Implement each `contracts/C-###.md` request and response shape, status code,
  and machine error code literally, including the JSON-RPC error codes the C-001 entry assigns; one
  entry per endpoint, and no endpoint invents its own envelope, field name, or numeric code. Every
  error row in every implemented contract gets an artifact-level conformance test asserting status,
  code, and body. A missing row for a real failure is a change request, not a new code.
- **Data hygiene at every boundary.** No secret, bearer token, private key, unmasked personal data, or
  raw tool argument or response payload reaches a log line, an audit record, an error body, or a
  metric. Log identity, tool name, verdict, count, and duration. Redact where the value enters the
  process. DLP runs before any outbound write of tool result content, including error and timeout
  paths, and a scanner failure masks rather than passes.
- **Configuration over code.** Host, port, upstream endpoints, policy documents, IdP and JWKS settings,
  approval webhooks, ledger location, and credentials are resolved from environment or YAML at
  startup. No literal endpoint, tenant name, machine-specific absolute path, or credential appears in
  production wiring, and a missing required setting fails startup with an error naming it instead of
  defaulting to a development value. Mock upstreams, allow-all interceptors, and permissive authorizers
  are test doubles: never a production default, never reachable through the shipped constructor. A new
  setting ships in the same change as the startup validation that rejects its absence.

## Checks

- Build and compile: `./gradlew :services:gateway:build`
- Run unit and integration tests: `./gradlew :services:gateway:test`
- Boot the gateway locally: `./gradlew :services:gateway:run` (exercise the affected path before
  calling the work done)

## Definition of Done

- All unit and integration tests in this directory pass.
- The artifact builds and boots, and the affected request path was exercised against the running
  server rather than inferred from a green suite.
- Contract conformance holds for the `contracts/C-###.md` rows the issue implements, including every
  error row.
- Every request-path class the change adds is reachable from `AegisGatewayServer`; no test-only
  production class remains.
- No secret, token, or unmasked identity appears in logs, audit records, error bodies, or responses.
- No blocking call runs on a Netty event-loop thread, and retained buffers are released on every path.
- Checks run cleanly with no unresolved stubs, placeholder responses, or TODOs.
- Missing contract fields, configuration, or specification answers are reported as gaps rather than
  improvised.

## Report

Task and feature IDs; files changed; endpoints and `C-###`; the handler and interceptor wiring added
to the composition root; test results; boot result; contract change requests; configuration keys
added; blockers or assumptions; commands run. Report contract conformance against the frozen
`contracts/C-###.md` shapes and error codes, and name any path that still depends on a mock upstream,
an allow-all interceptor, or a permissive authorizer.
