# apps/cli

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

## Area discipline

- Implement CLI commands cleanly with structured argument parsing and POSIX exit codes (0 for success, non-zero for errors).
- Manage child process lifecycles hermetically: handle SIGINT/SIGTERM, drain stdio pipes without deadlock, and propagate child exit codes.
- Render clean terminal output with color-coded logging and human-readable error messages.
- Ensure offline validation commands (such as policy linting) run fast without external network dependencies.

## Checks

- Build executable distribution: `./gradlew :apps:cli:build`
- Run unit and CLI interaction tests: `./gradlew :apps:cli:test`
- Run CLI application: `./gradlew :apps:cli:run --args="<command>"`

## Local Definition of Done

- All unit tests in this directory pass.
- Checks run cleanly with no unresolved stubs or TODOs.
