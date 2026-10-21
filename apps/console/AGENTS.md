# Frontend

<!-- profile: frontend -->

This file is a rule set for this area, not an agent role. It is authoritative for work here. Root
`AGENTS.md` is the coordinator's manual: read it when you plan, route, or run a phase gate — not to
implement a task.

## Scope

This directory and its subdirectories. The issue's `Own` and `Read-only` fields are binding.

## Task rules

- Work only inside the issue's `Own` paths; everything under `Read-only` is read-only.
- Code tasks never write under `docs/`. A doc gap becomes a `doc-gap` issue.
- Commit only your owned paths. Conventional Commits with `Implements: FEAT-###`. Never `git add -A`.
- Branch from `main`, open a PR, never push to `main`.
- Durable text cites `FEAT-###`, `NFR-###`, or `C-###`; never a task ID, route file, or issue number.
- Never log or commit secrets, tokens, or unmasked identity; credentials live in the secret store.
- No markdown documentation files; document inline.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- If a shared module or earlier-phase code needs a change, report it; do not make it.
- If blocked, work under a stated assumption when safe, or report it unimplemented. Do not ask the user.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Frontend discipline

- Build only through theme tokens. Never hardcode a hex, spacing, radius, or timing at a call site.
  When the token map keys a value by device class, apply the declared classes rather than collapsing
  them.
- Cover every state for every screen: loading, empty, error, offline, submitting, and validation.
- Follow the navigation map: drill-down pushes, a tab switch selects, return-to-landing resets, and
  a modal is dismissed by the scope that opened it.
- Reach craft through the platform kit: theme, then compose, then custom. A custom component
  inherits states, semantics, motion, reduced motion, 44px touch targets, contrast, and token
  theming.
- Wire to the frozen shapes and mock data until the endpoint is live.
- Read asset paths from `ASSETS.md`; never generate an asset or invent a missing one.
- Run the app and view every rendered state before calling it done.

## Checks

- The foundation task defines the commands for this area.

## Local Definition of Done

- Every screen state has a passing component or unit test.
- No design value is hardcoded.
- The rendered result was viewed and judged, not only compiled.
- Missing tokens or assets are reported.

## Report

Task and feature IDs; files changed; screens and states covered; unit-test results; missing
tokens or assets; shared-module changes; blockers or assumptions; commands run.
Report contract conformance against the frozen shapes.
