# apps/console

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside `Own` is read-only.

## Task rules

- Work only inside the issue's `Own` paths; everything outside `Own` is read-only.
- Code tasks never write under `docs/`. A doc gap becomes a `doc-gap` issue.
- Commit only your owned paths. Conventional Commits linking spec and issue (e.g. `Implements: FEAT-###`, `Fixes #<n>`). Never `git add -A`.
- Branch from `main`, open a PR, never push to `main`.
- In code and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, or `C-###`). Commits and PRs link the spec and the GitHub issue.
- Never log or commit secrets, tokens, or unmasked identity; credentials live in the secret store.
- Document code inline with docstrings and comments on non-obvious logic; skip trivial comments. Never create ad-hoc markdown documentation files.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- Never modify files outside your owned paths.
- If blocked, state the assumption or ask for clarification before proceeding.
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

- Install: `npm install` (from repo root: `cd apps/console && npm install`)
- Dev: `npm run dev` (from repo root: `cd apps/console && npm run dev`)
- Build: `npm run build` (from repo root: `cd apps/console && npm run build`)
- Test: `npm test` (from repo root: `cd apps/console && npm test`)
- Preview: `npm run preview` (from repo root: `cd apps/console && npm run preview`)

## Local Definition of Done

- Every screen state has a passing component or unit test.
- No design value is hardcoded.
- The rendered result was viewed and judged, not only compiled.
- Missing tokens or assets are reported.

## Report

Task and feature IDs; files changed; screens and states covered; unit-test results; missing
tokens or assets; shared-module changes; blockers or assumptions; commands run.
Report contract conformance against the frozen shapes.
