# Infrastructure

<!-- profile: infra -->

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

- The foundation task defines the commands for this area.

## Local Definition of Done

- The project builds from a clean checkout.
- Install, build, test, and boot commands run locally and in CI.
- Deploy is repeatable through those documented commands.
- No secret or real-value env file is in the repository.
- Any config another area must know is in the report.

## Report

Slice delivered; files changed; checks run and output; environment and secrets setup; shared config
another area must know; blockers or assumptions; commands run.
