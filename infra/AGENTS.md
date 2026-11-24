# infra

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside `Own` is read-only.

## Structure

- `docker/` — image definitions for every deployable this repository ships. One file named
  `Dockerfile` per image, selected with `-f`. The build context is always the repository root, so
  the Gradle wrapper, settings, and module build files resolve exactly as they do in CI.
  - `docker/Dockerfile` — the gateway image. The builder stage produces the gateway distribution;
    the runtime stage carries only the installed distribution, a JRE, the healthcheck, and the
    entrypoint.
  - `docker/build-image` (`build-image.ps1` on Windows) — the supported build path. It stamps the
    OCI revision and version, writes the SPDX SBOM to `docker/build/` with Trivy, and fails the
    build on a CRITICAL or HIGH vulnerability or any embedded secret before an image is released
    (NFR-028, NFR-023).
  - `docker/healthcheck.sh` — the image's liveness probe; it targets `GET /health` (C-022) on the
    configured port with the scheme the listener actually serves.
- `compose/` — local and CI multi-container topologies: the gateway plus the upstream tool servers
  it fronts. Compose files reference images built from `docker/`; they never redefine the image,
  introduce build-only environment differences, or substitute a third-party image for a product
  service. The topology's environment template (`.env.example`) lists every variable it accepts,
  with placeholders only.
- `helm/` — Kubernetes deployment assets. One chart directory per deployable, chart defaults in
  `values.yaml`, and per-environment overrides in separate values files. Probes, security context,
  resources, and volume mounts live in the chart, never in the image.
- Placement: a new image definition goes in `docker/`; new local service wiring goes in `compose/`;
  a new cluster asset goes in `helm/`. A Dockerfile never lives inside a service directory. A shell
  script is added only when a documented command cannot express the step, and it sits next to the
  asset that uses it.
- Build-context ignore rules belong to the repository-root `.dockerignore`: Docker reads the ignore
  file only from the context root, never from `infra/docker/`. Adding or changing it is a root-owned
  change requested through the coordinator.
- This directory carries no unit tests. Container and deployment verification belongs to a `verify`
  task under `tests/`; do not add a test tree here.

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

- **Reproducible builds.** Pin every base image by version tag and digest; `latest` is never a valid
  reference. Build only from the repository root against `-f infra/docker/Dockerfile`, copy only the
  declared inputs into each stage, and produce the runtime payload with the same Gradle task the
  suite exercises (`:services:gateway:installDist`), so the image and CI ship identical bytes. No
  absolute host paths in any build input, and no second hand-assembled build path.
- **Least privilege.** The runtime stage runs as a non-root user with a fixed numeric uid/gid. The
  deployment asset drops all capabilities, sets `no-new-privileges`, and gives the container a
  read-only root filesystem with one explicit writable volume for the audit ledger and its
  write-ahead log. Secrets never enter image layers, `ENV`, `ARG`, labels, or the build context;
  credentials are mounted or injected at runtime from the secret store or Kubernetes Secrets
  (NFR-023). Build arguments carry configuration only.
- **Runtime contract.** Configuration arrives exclusively as environment variables; the image bakes
  no environment-specific value and reads no configuration file from its own filesystem. Variable
  names, the listen port, and the health/readiness endpoint the interface contract defines stay
  consistent across the Dockerfile, compose file, chart, and probes — changing one changes all; an
  undocumented probe path is a change request against the contract. TLS key material is mounted at
  runtime, never baked, and the image ships no cleartext-serving default (NFR-021). The entrypoint
  uses exec form so SIGTERM reaches the JVM, and the process drains in-flight connections and exits
  within the termination window the release plan sets.
- **Environment parity.** Local, CI, staging, and production run the same image built from the same
  Dockerfile; promotion carries the image digest unchanged (see `release.md`). A compose file, chart,
  or values file may change configuration only — never the image contents, the build path, or the
  command. Per-environment Dockerfiles, hand-edited containers, and any manifest referencing
  `latest` are prohibited.
- **Observability.** Application logs go to stdout/stderr as structured single-line records; the
  image adds no log files, rotation, or shipping sidecar. No secret, token, or unmasked identity is
  written to logs (NFR-023, NFR-043). Health and readiness signals are reachable on the documented
  endpoint and port so the orchestrator can restart, drain, or roll back without shell access to the
  container.
- **Supply chain.** Every third-party image, base image, CLI tool, and scanner is version-pinned and
  recorded next to the asset that uses it. No download-and-execute installer, no unpinned binary
  fetch, and no package-manager upgrade at runtime. Each image build produces an SBOM and fails the
  pipeline on a finding that violates the vulnerability policy in NFR-028.
- **Application boundary.** Application source, tests, and the Gradle build are read-only here.
  This area changes packaging, the runtime contract, and deployment assets only; a defect in
  startup, configuration parsing, or shutdown behavior is reported to the owning area, never patched
  from this directory.

## Checks

- Build the gateway distribution: `./gradlew :services:gateway:installDist`
- Build and gate the gateway image from the repository root: `infra/docker/build-image`
  (`pwsh infra/docker/build-image.ps1` on Windows). It runs `docker build` from the root against
  `-f infra/docker/Dockerfile`, writes the SBOM, and fails on a policy violation.
- Boot smoke: `docker run --rm -p 8443:8443 aegismcp-gateway:local`, confirm the startup log line,
  send SIGTERM, and confirm a clean exit.
- Full build and suite when the image or a shared build input changes: `./gradlew build` and
  `./gradlew test`

## Definition of Done

- All unit tests in this directory pass.
- Checks run cleanly with no unresolved stubs or TODOs.
- The image builds from a clean checkout with no host path, no secret, and no writable root
  filesystem at runtime.
- Local, CI, and cluster assets reference the same image and the same environment variable names.
- The Dockerfile and every manifest carry no `latest` reference and no unpinned download.

## Report

Slice delivered; files changed; checks run and output; environment and secrets setup; shared config
another area must know; blockers or assumptions; commands run.
