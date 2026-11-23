# AegisMCP — build guide

This repository is built from its specification by whichever coding agent is working in it. The rules
live with the code: this file coordinates the build, and the nearest `AGENTS.md` in a folder governs
work in that folder.

## Source of truth

The specification is `docs/AegisMCP/`. `docs/` is a git submodule of the `aegismcp-docs` repository.

A build task never edits the specification. A gap in it becomes a `doc-gap` issue, not an assumption
and not a silent change.

### Specification modifications & subagent isolation

The specification is modified only in these situations:
1. **Unsettled requirement (`doc-gap`):** an implementation or verification task discovers an unhandled
   edge case, missing data field, ambiguous behavior, or conflicting requirement. The worker pauses,
   logs the `doc-gap` issue, and halts implementation on that path.
2. **User-directed change:** the user requests a scope adjustment, new feature addition, or requirement
   revision.
3. **Architectural or platform shift:** structural, scaling, or environmental changes require updating
   `architecture.md`, `schema.md`, or `nfr.md`.

**Mandatory subagent isolation:** spec modifications must **never** run inside an active coding or
debugging session. Mixing compiler logs, code diffs, and stack traces into specification writing
contaminates the product requirements. The coordinator dispatches a dedicated, isolated subagent
targeting `docs` with a clean context window. That subagent loads `docs/AGENTS.md`, aligns with the
user, updates the specification under `docs/AegisMCP/`, and commits the changes. The implementation
session resumes only after the specification is committed, reading the updated documents as its single
source of truth.

## Where truth lives

| Question | Source | How to read it |
|---|---|---|
| What to build | `docs/AegisMCP/` | read the named document |
| Current phase | Lowest open `phase` issue | `gh issue list --label phase --state open` |
| Task scope | Issue body | `gh issue view <n>` |
| Ready work | Blocked-by links | `gh issue list --state open`, then `gh issue view <n> --json blockedBy` |
| Task status | Issue state | `gh issue view <n> --json state` |
| In flight | Pull requests | `gh pr list --state open` |
| Why a choice | `.decisions/` | `ls .decisions/`, `git log -- .decisions/` |
| Interfaces | `contracts/` | `contracts/C-###.md`, indexed by `contracts/README.md` |
| Asset paths | `assets/ASSETS.md` | the `A-###` row |
| Area rules | nearest `AGENTS.md` | `git ls-files '*AGENTS.md'` |
| Done | this file | Definition of Done and Verification |

State that changes per task or phase lives in GitHub. Decisions that outlive a task live in this
repository. Never copy live state into a file.

## Stack

| Concern | Choice | Note |
|---|---|---|
| Core Gateway | Java 21, Netty 4.1, Loom virtual threads | NFR-001 latency, NFR-002 concurrency |
| Build Tool | Gradle 9.3.1 (Kotlin DSL) | Hermetic multi-project builds via `gradlew` |
| Serialization | Jackson 2.17.2 | JSON-RPC and YAML policy parsing |
| CLI | picocli 4.7.6 | POSIX exit codes and terminal output |
| Console Frontend | React 19, TypeScript 5.7, Vite 6, Tailwind CSS 3.4 | Decoupled security-operations SPA |
| Console Tests | Vitest 3, Testing Library | Component and state coverage |
| E2E & Verification | JUnit 5.10.2, JDK HttpClient, Netty | Black-box artifact harness |

Identity validation currently uses the JDK X.509 and signature APIs. See
`.decisions/ADR-002-stack-reconciliation.md` before adding a cryptography, container, or browser
dependency; the recorded stack must match the manifests.

Changing a stack choice is a decision: record it in `.decisions/` and update this table.

## Repository structure

```text
services/gateway   Netty gateway, security pipeline, management endpoints
apps/cli           aegis-cli developer and operator tool
apps/console       React security console
tests/e2e          black-box harness and contract conformance tests
infra              container and deployment assets
assets             brand source files and the asset ledger
contracts          interface contracts, one file per C-###
docs               specification submodule (aegismcp-docs)
.decisions         architecture decision records
```

## Area rules

Area rules live in the nearest `AGENTS.md`: any coding agent working in the area loads them.
Read the nearest `AGENTS.md` at or above the issue's `Own` paths. List them with
`git ls-files '*AGENTS.md'` or `find . -name AGENTS.md`.

## Work classes

Every task is exactly one class:

- `implement` — writes product code, assets, and configuration under the issue's `Own` paths.
- `fix` — repairs a defect against existing requirements under the issue's `Own` paths.
- `verify` — writes test files and test configuration only, under the phase gate.
- `spec` — writes only under `docs/AegisMCP/`, governed by `docs/AGENTS.md`. Always executed in an
  isolated subagent.
- `chore` — repository plumbing with no product behavior change.

Asset work is `implement` work whose `Own` paths are the slots recorded in `assets/ASSETS.md`.

## Build workflow

1. **Read the specification.** Resolve `docs/AegisMCP/` and read every document at plan level:
   scope, users, features, NFRs, roadmap, architecture, data, screens, monetization, risks. The docs
   are the authority; recall is not.
2. **Adopt the roadmap.** Take its phases and their order as the build order. Do not re-sequence or
   re-group them. If the roadmap is missing or silent on order, raise a doc gap. Integration recovery
   is Phase 4 of the roadmap and is gated like every other phase.
3. **Phase 0: Foundation.** Before any roadmap feature phase is implemented, Phase 0 (Foundation) must
   be drafted, executed, and verified. Foundation sets up:
   - Toolchains and pinned manifests: the Java 21 toolchain and Gradle wrapper (`gradlew`,
     `settings.gradle.kts`), `services/gateway/build.gradle.kts`, `apps/cli/build.gradle.kts`,
     `tests/e2e/build.gradle.kts`, and `apps/console/package.json` with its lockfile;
   - Verified Git and GitHub infrastructure (remote repository configured, `phase` label created,
     `gh` CLI operational with sub-issues and blocked-by dependencies, and default branch protection
     enabled);
   - Verified commands (build, test, boot, lint) in scripts or a Makefile;
   - CI/CD workflow (`.github/workflows/ci.yml`) running the gateway, CLI, console, and artifact
     suites as required jobs;
   - A base test harness and an artifact boot check that starts the packaged gateway and exercises
     `/health` and `POST /mcp/v1/rpc` through the production composition root;
   - Design tokens and a theme provider for the visual console;
   - Operational baseline: health endpoint, structured logging, and configuration loading from
     environment/YAML;
   - Foundational assets: any `Pending` core brand asset declared in `assets/ASSETS.md`.
   Roadmap feature phases (Phase 1..N) are strictly blocked by Phase 0.
4. **Confirm frozen contracts.** Verify that every `contracts/C-###.md` an issue names is `Frozen`
   before the issue dispatches. Any interface modification requires an approved `change-request`
   issue that updates the contract and both sides in one PR.
5. **Draft the dispatch plan.** One phase issue for Phase 0 and one phase issue per roadmap phase from
   the phase template, each parented with child task issues from the task template.
   - **Declare the Phase Specification Slice:** in each phase issue, record the complete specification
     slice the phase delivers: roadmap features (`FEAT-###`), screens (`screens/*.md`), data entities
     (`schema.md`), contracts (`contracts/C-###.md`), telemetry events (`analytics.md` `EVT-###`),
     quantitative NFRs (`nfr.md`), and monetization gates (`monetization.md`).
   - **Decompose features across declared areas for parallel dispatch:** slice features by area and
     frozen contract (`C-###`) so workers execute concurrently. Client tasks map to screens and theme
     tokens; service tasks map to contracts, schema migrations, and service NFRs; CLI tasks map to
     commands, arguments, and terminal output. Decompose only across surfaces the specification
     defines.
   - Every task carries `Depends on` — the issue numbers that must close first, or `none`. Tasks in
     different areas bound to a frozen contract run concurrently.
   - Present the tree — phases, tasks, edges — and create nothing yet.
6. **Create the plan on agreement.** After the user agrees, create the `phase` label if it is missing
   (`gh label create phase`), then the phase issues in order with `gh issue create --label phase`,
   then each task with `gh issue create --parent <phase>`, then every dependency with
   `gh issue edit <n> --add-blocked-by <dep>`. Change the draft when the user asks.
7. **Ask about dispatch.** With the issues in GitHub, ask once whether to dispatch subagents or work
   them in this session. Follow Dispatch below.
8. **Gate each phase.** The gate is a `verify` task, parented to the phase and blocked by every other
   task in it. When those tasks are closed, verify the deliverable against the phase's full
   Specification Slice (contracts, acceptance criteria, screen completeness, schema migrations,
   telemetry events, and NFR budgets) and the full regression suite. Close the phase issue only when
   the gate passes.

## Dispatch

The user decides who does the work. Once the plan exists, ask once whether to dispatch subagents or
work the issues in this session. Either answer is valid, the answer holds for the plan, and the user
can stop it at any point.

- **Draft, approve, then create.** The phase issues, the task issues, and their dependencies are a
  draft. Create them only after the user agrees, and change the draft when they ask.
- **The graph is the schedule.** A task is ready when it is in the lowest open phase and every issue
  blocking it is closed. Tasks with no edge between them may run at the same time and in any order.
  The parent phase groups its tasks; it does not order them.
- **A frozen contract is a precondition.** An issue whose `C-###` is not `Frozen` is not ready, even
  with its blockers closed.
- **Subagent dispatch prompt.** When dispatching a subagent for a task, the subagent prompt is strictly
  the issue identifier:

  ```
  Issue: #<number>
  ```

  Never restate the issue description, acceptance criteria, or boundaries in the dispatch prompt. The
  subagent runs `gh issue view <number>` to read the task contract (`Class`, `Own`, `Depends on`,
  `Contract`, `Specification`, `Criteria`).
- **Task execution.** A worker focuses on its assigned issue, reads the nearest `AGENTS.md` at or above
  its `Own` paths and the documents it names, stays within its owned paths, and reports back on
  completion.
- **Tasks are leaves.** Only a phase issue has sub-issues. Never nest a task under a task.
- **A phase issue is never dispatched.** It groups its tasks and parents the gate.
- **The coordinating session works too.** When the user keeps the work here, do it under the same
  dependency rule.
- **Spec task isolation.** When dispatching a `spec` task or resolving a `doc-gap`, always run it in an
  isolated subagent targeting `docs/`. Never execute spec tasks in an active implementation session.
- **The phase gate.** Verify the phase with a clean test and boot sweep against the criteria before
  closing the phase issue.

## In-flight feedback and defect triage

When the user points out a defect, missing behavior, or desired change in conversation—whether during
an active phase or after earlier tasks have closed—never jump directly into editing code. Impromptu
edits bypass verification, violate path boundaries, and create fragmented issue churn.

Follow this triage protocol:

1. **Inspect and trace first.** Before proposing a fix or opening an issue, inspect the relevant
   codebase, test suites, and specification. Identify the true root cause and trace all affected
   surfaces (client UI states, service endpoints, data models, contracts).
2. **Conduct a diagnostic interview.** Ask targeted, clarifying questions to establish complete intent:
   whether the feedback is an implementation bug against the existing specification or an intentional
   shift in product requirements; edge-case behavior; and whether adjacent screens, commands, or
   workflows should follow the same pattern.
3. **Consolidate and propose the scope.** Synthesize the findings into one clear diagnosis and present
   a single comprehensive plan rather than fragmented, symptom-by-symptom issues.
4. **Contract-first execution:**
   - For defects or implementation gaps against existing requirements: draft a `Class: fix` task
     parented to the active phase issue, establish exact `Own` boundaries, confirm with the user,
     create the issue, and dispatch.
   - For requirement shifts or new features: dispatch an isolated subagent under `docs/AGENTS.md` to
     update the specification first, commit it separately, and then draft the implementation task(s).
   - For interface or data-schema changes: file a `change-request` issue that revises the contract
     before updating application code.

## Task contract

Every task is an issue from `.github/ISSUE_TEMPLATE/task.md`, parented to its phase issue, with:

- `Class` — implement, fix, verify, spec, or chore.
- `Own` — the paths the task may write; everything outside `Own` is read-only. The nearest `AGENTS.md`
  at or above `Own` governs the work.
- `Depends on` — the issue numbers that must close first, or `none`. The issue's blocked-by links
  mirror this line; when they disagree, the issue body is the record and the coordinator fixes the
  links.
- `Contract` — the `C-###` it implements, or `none`.
- `Specification` — the specific feature (`FEAT-###`), screens, schema entities, telemetry events
  (`EVT-###`), or NFRs assigned to this task.
- `Criteria` — where the acceptance criteria live (e.g. `features/FEAT-###.md`, screens, or a
  contract).

A task closes when its PR merges and the issue closes. There is no route file and no separate delivery
board.

## Interface contracts

Interfaces live in `contracts/`, one file per contract (`contracts/C-###.md`), indexed by
`contracts/README.md`. Each entry carries its status, owner, authentication, exact request and response
shapes, every error condition, and a conformance binding.

- `Draft` — under discussion; not dispatchable.
- `Frozen` — both sides agree; implementing tasks may dispatch.
- `Implemented` — a conformance test passes against the packaged artifact in CI.

A contract without a passing artifact-level conformance test is not `Implemented`. A change after
`Frozen` is a `change-request` issue and a PR that updates the contract and both sides together. Never
deviate silently.

## Assets

`assets/ASSETS.md` is the ledger: one row per slot, plus the family block whose prompt produced it. The
user is the sole authority on what already exists and where. Agents read the ledger and never invent a
missing asset. Asset work follows `assets/AGENTS.md`.

## Definition of Done

A task is done when:

- its unit tests pass;
- its frozen contract has a conformance test that passes against the packaged artifact;
- the capability is assembled in the production composition root, not only in a test fixture;
- only its owned paths changed;
- all states and specifications assigned to the task are fully implemented;
- no placeholder, stub, or `TODO` remains;
- the packaged artifact builds and boots;
- user-facing copy reads as human-written.

A phase is done when its gate task passes and the phase issue closes.

## Verification

A phase is verified after all its tasks are done.

Inputs: the phase's tasks, `contracts/`, the acceptance criteria those issues name, the parent phase's
Specification Slice, the quality bar in `nfr.md`, and the commands in this file.

1. Build the deliverable the way it ships and boot it. A green suite is not proof it runs; the build
   and the boot are. On failure, report the log.
2. Run the full suite, not the slice.
3. Write the integration, end-to-end, and acceptance tests the criteria require. Test the packaged
   artifact: the end-to-end harness launches the packaged gateway or production main class and must
   not instantiate gateway handlers, interceptors, or Netty pipelines. Fixtures may provide only mock
   upstream servers, identity material, and test data. Unit tests belong to the implementers; do not
   duplicate them.
4. Verify behavior against the criteria and the contracts, not pixels.
5. Verify screen completeness: when visual interfaces are declared, confirm that all declared screen
   states (empty, loading, error, submitting, success) are implemented and functional rather than
   stubbed.
6. Verify telemetry: when analytics are declared, confirm that declared events (`EVT-###`) fire with
   schema-valid payloads during user flows.
7. Verify quantitative NFRs: measure latency as added latency against a direct-upstream baseline on
   the same host; test password hashing standards, session TTLs, and rate limits. Report the metric,
   the sample size, and the failing cases.
8. When the product has model-backed behavior, run the golden set against the pinned model, compute
   the metric, and compare it to `NFR-###`. Report the metric, sample size, pass rate, and failing
   cases.
9. Treat placeholders, stubs, `TODO`s, and "just for now" shortcuts as Definition-of-Done failures.
10. Report each failure with file/line and expected vs actual. Never fix it.

Write only test files and test configuration; feature code is read-only. Never tune a threshold or the
evaluation set to make a run pass. Never disable the build check to reach a green gate. Never accept a
capability that exists only in a test fixture. If a requirement has no acceptance criterion, report a
doc gap; do not invent the test. Do not judge appearance; that belongs to the frontend.

## Git and GitHub

- `main` is protected. Work on a short-lived branch and open a PR.
- Branch naming: `<class>/<issue-number>-<slug>` where `<class>` matches the task class (`implement`,
  `fix`, `verify`, `spec`, `chore`), `<issue-number>` is the GitHub issue number without `#`, and
  `<slug>` is a short kebab-case description or spec anchor (e.g. `implement/12-feat-001-auth`).
- Conventional Commits. Commits link the spec and the issue: e.g. `Implements: FEAT-###` and
  `Fixes #<n>`.
- Commit only the paths the issue owns. Never `git add -A`.
- A PR carries the issue number, the `C-###` it conforms to, and the checks run.
- A phase issue closes only after its gate task passes.
- Sub-issues and dependencies need GitHub CLI 2.94.0 or newer: `--parent`, `--add-sub-issue`, and
  `--blocked-by`.
- The specification is a submodule: spec changes commit in `aegismcp-docs`; the pointer bump is its
  own PR.

## Decisions

`.decisions/ADR-###-<slug>.md`, one decision per file, append-only. A decision records the choice, the
reason, and the consequences. Supersede a decision with a new file; never rewrite an accepted one.

## Commands

| Command | Run |
|---|---|
| Build full project | `./gradlew build` |
| Test full suite | `./gradlew test` |
| Build gateway distribution | `./gradlew :services:gateway:installDist` |
| Boot Gateway Server | `./gradlew :services:gateway:run` |
| Run CLI | `./gradlew :apps:cli:run --args="--help"` |
| Build Web Console | `cd apps/console && npm ci && npm run build` |
| Test Web Console | `cd apps/console && npm test` |
| Run E2E and contract suite | `./gradlew :tests:e2e:test` |

Phase 0 adds the packaged-artifact boot check and CI wiring for these commands.

## Boundaries

- Never write under the specification path from an implementation task.
- Never invent a requirement. A missing answer is a doc gap.
- Never log or commit secrets, tokens, or unmasked identity.
- Never tune a test, threshold, or evaluation set to make a run pass.
- Never add a markdown document where inline documentation is enough.
- Never let a capability exist only in a test fixture; if the packaged artifact does not assemble it,
  it is not built.
- In durable code comments and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, `EVT-###`,
  or `C-###`). Commits and PRs link the spec and the GitHub issue.
