# services/gateway

This file is a rule set for this area, not an agent role. It is authoritative for work here. Root
`AGENTS.md` is the coordinator's manual: read it when you plan, route, or run a phase gate — not to
implement a task.

## Scope

This directory and its subdirectories. The issue's `Own` and `Read-only` fields are binding.

## Task rules

- Work only inside the issue's `Own` paths; everything under `Read-only` is read-only.
- Code tasks never write under `docs/`. A doc gap becomes a `doc-gap` issue.
- Commit only your owned paths. Conventional Commits linking spec and issue (e.g. `Implements: FEAT-###`, `Fixes #<n>`). Never `git add -A`.
- Branch from `main`, open a PR, never push to `main`.
- In code and tests, cite permanent spec anchors (`FEAT-###`, `NFR-###`, or `C-###`). Commits and PRs link the spec and the GitHub issue.
- Never log or commit secrets, tokens, or unmasked identity; credentials live in the secret store.
- No markdown documentation files; document inline.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- Respect the issue's `Own` and `Read-only` boundaries; do not modify files outside your owned paths.
- If blocked, state the assumption or ask for clarification before proceeding.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Backend discipline

- Implement the frozen contract exactly: request and response shapes, status codes, and error codes.
- Own persistence, auth, and the server-side enforcement of gates and billing.
- Validate at the boundary; never trust client input.
- Keep secrets, tokens, and unmasked identity out of logs and error responses.

## Checks

- The foundation task defines the commands for this area.

## Local Definition of Done

- Unit tests pass and cover the contract's edge and failure paths.
- The response matches the contract exactly.
- No secret, token, or identity leak in logs.
- Every assumption or blocker is in the report.

## Report

Task and feature IDs; files changed; endpoints and `C-###`; test results; contract change requests;
shared-module changes; blockers or assumptions; commands run.
