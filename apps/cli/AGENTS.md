# apps/cli

This file is authoritative for work in this directory and its subdirectories. Root
`AGENTS.md` is the coordinator's manual: read it for repository-wide workflow, dispatch,
and verification gates.

## Scope

This directory and its subdirectories. The issue's `Own` paths are binding; everything outside `Own` is read-only.

## Structure

- `apps/cli` is the Gradle subproject `:apps:cli`. `build.gradle.kts` names the entrypoint class and
  the distribution; it is the only place build or dependency changes go. `build/` is generated output —
  never edit, and never add files to it.
- `src/main/java/dev/aegismcp/cli/` is the only production code root. The package is intentionally flat:
  one command or one transport collaborator per file, no nested feature packages.
  - `AegisCliMain` is the picocli entrypoint: the root command, the subcommand registry, and the
    `execute` seams the tests call. A new subcommand is registered here and nowhere else.
  - `WrapCommand`, `LintCommand`, `KillCommand` are command classes. A command parses options,
    validates its inputs, delegates the work, and translates the outcome into an exit code. It holds no
    protocol parsing, no log rendering, and no socket handling of its own.
  - `StdioProxy` owns the JSON-RPC stdio pump and the managed child process: spawn, concurrent drain,
    shutdown, and exit-code propagation.
  - `TerminalInspector` owns everything written to the inspection channel: banner, per-call verdict,
    messages, errors, and the single decision of whether to emit color.
- `src/test/java/dev/aegismcp/cli/` mirrors the production package: one `XxxTest` class per subject,
  in the same package. There is no second test source set and no separate test module.
  - `MockMcpChildServer` is the shared child-process fixture. Extend it for a new upstream behavior
    instead of spawning ad-hoc processes inside a test body.
  - Command tests drive the command instance or the `execute` seam with captured writers. They never
    call `System.exit` and never depend on the developer's terminal.
- Where new work lands:
  - new subcommand → its own `*Command` class plus a registry line in `AegisCliMain`;
  - pipe, framing, or child-lifecycle change → `StdioProxy`;
  - banner, verdict, color, or plain-text change → `TerminalInspector`;
  - gateway HTTP call → the command that exposes it, serialized through the shared gateway types already
    on the module's compile path, not hand-built JSON.
- Anything that ships inside the binary goes under `src/main/resources/`; test-only data stays in the
  test tree. Ad-hoc markdown, sample output dumps, and scratch scripts are not added to this module.

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

- **POSIX exit codes.** Return 0 only on success. Every failure path — bad option, unreadable policy,
  rejected policy compile, gateway non-2xx, transport failure, child abort — returns a documented
  non-zero code and writes the reason to stderr. No catch block may fall through to 0, and no branch may
  return a code the module does not document. Parse errors raised by the command framework count as
  failures too: map them explicitly instead of inheriting a silent default, and keep the mapping in one
  place that a test asserts.
- **TTY-aware output.** Resolve color once, at the command boundary, through an explicit
  `--color=auto|always|never` switch; `auto` means an interactive terminal only. Pipe or redirect means
  plain text. `NO_COLOR` and a dumb terminal force plain text regardless of the flag. Machine-readable
  channels — JSON-RPC frames on stdout, lint reports, kill-switch results — never contain ANSI escapes,
  even when color is forced; escapes belong to the stderr inspection lines alone. Capture piped output
  in a test and assert the escape byte is absent.
- **Hermetic child lifecycle.** Launch the child only after argument, policy, and path validation has
  passed, so a usage error exits before any process exists. Drain the child's stdout and stderr
  concurrently from the first byte and never block on process exit with a pipe undrained. Close child
  stdin on parent EOF, and terminate the child on interruption and in a `finally`, escalating a polite
  destroy to a forced kill on a bounded timeout, so no orphan outlives the CLI. Return the child's exit
  code as the command's exit code; never replace it with 0.
- **Offline validation.** `lint` and every policy check resolve and compile from the local filesystem
  only — no socket, no gateway call, no remote schema fetch — and finish without network access. Reject
  empty, missing, unreadable, and malformed input before analysis, naming the file and the offending
  field or line with what was expected and what was found. Unreachable-rule warnings do not fail the
  run, but they are always printed; never swallow them.
- **Security hygiene.** Never print a bearer token, credential, or unmasked PII — not whole, not
  truncated, not in an error message. Inspection logs render tool arguments only to the level the
  specification requires, through the same redaction path the gateway applies; below that level,
  summarize instead of dumping raw arguments. Gateway error bodies are not echoed verbatim; print the
  status plus a redacted message. Credentials come from the environment or the secret store, never from
  a positional argument that lands in shell history.
- **Contract conformance.** A command that calls a gateway endpoint implements the frozen contract
  in `contracts/C-###.md` exactly: method, path, headers, request body, success shape, and every
  documented error status. Give each documented status its own non-zero exit and a human message;
  unknown statuses fail generically rather than being read as success. Deserialize into the shared
  response types and do not invent enum values or fallback strings the contract does not define.

## Checks

- Build: `./gradlew :apps:cli:build`
- Test: `./gradlew :apps:cli:test`
- Run: `./gradlew :apps:cli:run --args="--help"`

## Definition of Done

- Every test under `src/test/java/dev/aegismcp/cli/` passes.
- The new behavior's success, validation-failure, child-failure, and gateway-failure paths each have a
  test that asserts the exit code, not just the message.
- Piped and redirected output carries no ANSI escapes, and forced color leaves stdout protocol frames
  clean.
- No child process survives the command, including when the parent is interrupted.
- No token, credential, or unmasked identity appears in any output path.
- Commands that call a gateway endpoint match the frozen shape and error mapping in `contracts/C-###.md`.
- No stub, `TODO`, or placeholder remains; the build and `--help` still run.

## Report

Task and feature IDs; files changed; commands added or changed with their exit codes; conformance to
`contracts/C-###.md`; unit-test results; color and piped-output behavior observed; blockers or
assumptions; commands run.
