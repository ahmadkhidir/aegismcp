# infra

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
- No markdown documentation files; document inline.
- Write lean unit tests for the behavior your issue names.
- If a contract is wrong or incomplete, report a change request; never deviate.
- Never modify files outside your owned paths.
- If blocked, state the assumption or ask for clarification before proceeding.
- When a fact resists you, verify it with evidence before falling back on recall.
- User-facing copy reads as human-written.

## Infrastructure discipline

- Scaffold and pin the stack the docs require; build only what they require.
- Keep environment configuration in one documented place. Use placeholders and `.env.example`; never
  a real-value env file.
- Define the exact install, build, test, and boot commands as the single source of truth.
- Wire the build into CI so a broken build or a project that will not start fails fast and prints its
  log.
- Keep the pipeline lean: run the suite the areas own; no coverage gates or redundant jobs.
- Never commit secrets; credentials live in the secret store.
- Application code is read-only.

## Checks

- Build Docker container: `docker build -f infra/docker/Dockerfile -t aegismcp-gateway:latest .`

## Local Definition of Done

- The project builds from a clean checkout.
- Install, build, test, and boot commands run locally and in CI.
- Deploy is repeatable through those documented commands.
- No secret or real-value env file is in the repository.
- Any config another area must know is in the report.

## Report

Slice delivered; files changed; checks run and output; environment and secrets setup; shared config
another area must know; blockers or assumptions; commands run.
