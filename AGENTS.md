# AegisMCP — build guide

This repository is built from its specification by whichever coding agent is working in it. The rules
live with the code: this file coordinates the build, and the nearest `AGENTS.md` in a folder governs
work in that folder.

## Source of truth

The specification is `docs/AegisMCP/`. Read it before planning or building.

A build task never edits the specification. A gap in it becomes a `doc-gap` issue, not an assumption
and not a silent change.

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
| Interfaces | `CONTRACTS.md` | the `C-###` entry |
| Asset paths | `ASSETS.md` | the `A-###` row |
| Area rules | nearest `AGENTS.md` | `git ls-files '*AGENTS.md'` |
| Done | this file | Definition of Done and Verification |

State that changes per task or phase lives in GitHub. Decisions that outlive a task live in this
repository. Never copy live state into a file.

## Stack

| Concern | Choice | Note |
|---|---|---|
| Core Gateway | Java 21, Netty 4.1, Loom Virtual Threads | Sub-5ms P99 overhead (`NFR-001`), 50k sessions (`NFR-002`) |
| Build Tool | Gradle 8.7 (Kotlin DSL) | Hermetic multi-project builds (`gradlew`) |
| Cryptography & Identity | Bouncy Castle, SPIFFE Java SDK | X.509 SVID validation & hardware-accelerated TLS 1.3 |
| Console Frontend | React 19, TypeScript, Vite, Tailwind CSS | Decoupled SPA for security operations center |
| E2E & Verification | JUnit 5, Testcontainers, Playwright | Containerized black-box test harness simulating MCP agents |

Changing a stack choice is a decision: record it in `.decisions/` and update this table.

## Area rules

Area rules live in the nearest `AGENTS.md`: any coding agent working in the area loads them. Start the
session in the area, or read its file when the issue names one. List them with `git ls-files '*AGENTS.md'`
or `find . -name AGENTS.md`.

## Work classes

Every task is exactly one class:

- `implement` — writes product code under the issue's `Own` paths.
- `verify` — writes test files and test configuration only, under the phase gate.
- `spec` — writes only under `docs/AegisMCP/`, governed by `docs/AGENTS.md`.
- `asset` — writes only under the asset paths, governed by the nearest asset `AGENTS.md` and
  `ASSETS.md`.

A code task never writes the specification. A spec task never writes code.
An asset task writes neither. The issue names the class and the area.

## Build workflow

1. **Read the specification.** Resolve `docs/AegisMCP/` and read every document at plan level:
   scope, users, features, NFRs, roadmap, architecture, data, screens, monetization, risks. The docs
   are the authority; recall is not.
2. **Adopt the roadmap.** Take its phases and their order as the build order. Do not re-sequence or
   re-group them. If the roadmap is missing or silent on order, raise a doc gap.
3. **Record the stack.** Put one question batch to the user with best-fit options and a
   recommendation. Record the choice in Stack and the reason in `.decisions/`.
4. **Freeze the interfaces.** When the product has interfaces, write the interface contract and
   present it for acknowledgment. A change after `Frozen` is a change request.
5. **Draft the dispatch plan.** One phase issue per roadmap phase from the phase template, then one
   task issue per task from the task template, each parented to its phase. Every task carries
   `Depends on` — the issue numbers that must close first, or `none`. Foundation work leads: scaffold,
   CI, and the pinned stack before feature work; when the product has assets, source its imagery
   once, before the screens that use it, and record each slot in the ledger. Present the tree — phase,
   tasks, edges — and create nothing yet.
6. **Create the plan on agreement.** After the user agrees, create the `phase` label if it is missing
   (`gh label create phase`), then the phase issues in roadmap order with
   `gh issue create --label phase`, then each task with `gh issue create --parent <phase>`, then every
   dependency with `gh issue edit <n> --add-blocked-by <dep>`. Change the draft when the user asks.
7. **Ask about dispatch.** With the issues in GitHub, ask once whether to dispatch subagents or work
   them in this session. Follow Dispatch below.
8. **Gate each phase.** The gate is a `verify` task, parented to the phase and blocked by every other
   task in it. When those tasks are closed, verify the deliverable against the acceptance criteria
   and full regression suite. Close the phase issue only when the gate passes.

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
- **Task execution.** A worker focuses on its assigned issue, reads the area file and documents
  it names, stays within its owned paths, and reports back upon completion.
- **Tasks are leaves.** Only a phase issue has sub-issues. Never nest a task under a task.
- **A phase issue is never dispatched.** It groups its tasks and parents the gate.
- **The coordinating session works too.** When the user keeps the work here, do it under the same
  dependency rule.
- **The phase gate.** Verify the phase with a clean test and boot sweep against the criteria before
  closing the phase issue.

## Task contract

Every task is an issue from `.github/ISSUE_TEMPLATE/task.md`, parented to its phase issue, with:

- `Class` — implement, fix, verify, spec, asset, or chore.
- `Area` — the folder whose `AGENTS.md` governs the work.
- `Own` — the paths the task may write. Everything outside `Own` is read-only.
- `Depends on` — the issue numbers that must close first, or `none`. The issue's blocked-by links
  mirror this line; when they disagree, the issue body is the record and the coordinator fixes the
  links.
- `Contract` — the `C-###` it implements, or `none`.
- `Specification` — the sections it needs.
- `Criteria` — where the acceptance criteria live.

A task closes when its PR merges and the issue closes. There is no route file and no separate
delivery board.

## Contracts

`CONTRACTS.md` holds one entry per interface. `Frozen` means both sides agree; `Implemented` means it
shipped and conforms. A change after `Frozen` is a `change-request` issue and a PR that updates both
sides. Never deviate silently.

## Assets

`ASSETS.md` is the ledger: one row per slot, plus the family block whose prompt produced it. The user
is the sole authority on what already exists and where. Agents read the ledger and never invent a
missing asset. Asset work follows the nearest asset `AGENTS.md`.

## Definition of Done

A task is done when:

- its unit tests pass;
- it conforms to the frozen contract;
- only its owned paths changed;
- no placeholder, stub, or `TODO` remains;
- the build and boot still work;
- user-facing copy reads as human-written.

A phase is done when its gate task passes and the phase issue closes.

## Verification

A phase is verified after all its tasks are done.

Inputs: the phase's tasks, `CONTRACTS.md`, the acceptance criteria
those issues name, the quality bar in `nfr.md`, and the commands in this file.

1. Build the deliverable the way it ships and boot it. A green suite is not proof it runs; the build
   and the boot are. On failure, report the log.
2. Run the full suite, not the slice.
3. Write the integration, end-to-end, and acceptance tests the criteria require. Unit tests belong to
   the implementers; do not duplicate them.
4. Verify behavior against the criteria and the contracts, not pixels.
5. When the product has model-backed behavior, run the golden set against the pinned model, compute
   the metric, and compare it to `NFR-###`. Report the metric, sample size, pass rate, and failing
   cases.
6. Treat placeholders, stubs, `TODO`s, and "just for now" shortcuts as Definition-of-Done failures.
7. Report each failure with file/line and expected vs actual. Never fix it.

Write only test files and test configuration; feature code is read-only. Never tune a threshold or
the evaluation set to make a run pass. Never disable the build check to reach a green gate. If a
requirement has no acceptance criterion, report a doc gap; do not invent the test. Do not judge
appearance; that belongs to the frontend.

## Git and GitHub

- `main` is protected. Work on a short-lived branch and open a PR.
- Conventional Commits. Commits link the spec and the issue: e.g. `Implements: FEAT-###` and `Fixes #<n>`.
- Commit only the paths the issue owns. Never `git add -A`.
- A PR carries the issue number, the `C-###` it conforms to, and the checks run.
- A phase issue closes only after its gate task passes.
- Sub-issues and dependencies need GitHub CLI 2.94.0 or newer: `--parent`, `--add-sub-issue`, and
  `--blocked-by`.
- If the specification is a submodule, spec changes commit in the spec repository; the pointer bump
  is its own PR.

## Decisions

`.decisions/ADR-###-<slug>.md`, one decision per file, append-only. A decision records the choice,
the reason, and the consequences. Supersede a decision with a new file; never rewrite an accepted
one.

## Commands

| Command | Run |
|---|---|
| Build full project | `./gradlew build` |
| Test full suite | `./gradlew test` |
| Boot Gateway Server | `./gradlew :services:gateway:run` |
| Run CLI | `./gradlew :apps:cli:run --args="--help"` |
| Build Web Console | `cd apps/console && npm run build` |
| Test Web Console | `cd apps/console && npm test` |

## Boundaries

- Never write under the specification path from an implementation task.
- Never invent a requirement. A missing answer is a doc gap.
- Never log or commit secrets, tokens, or unmasked identity.
- Never tune a test, threshold, or evaluation set to make a run pass.
- Never add a markdown document where inline documentation is enough.
- In durable code comments and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, or `C-###`). Commits and PRs link the spec and the GitHub issue.
