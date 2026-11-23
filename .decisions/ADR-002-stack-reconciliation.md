# ADR-002: Stack reconciliation

- Status: Accepted
- Date: 2026-11-23

## Context

Two accepted records shared the ADR-001 number (`ADR-001-stack-selection.md` and `ADR-001-stack.md`)
and described a stack the repository does not build. They claimed Gradle 8.7, Bouncy Castle, the SPIFFE
Java SDK, Nimbus, Chronicle Queue, the LMAX Disruptor, Testcontainers, and Playwright. The repository
pins Gradle 9.3.1, has no dependency on any of those libraries, and implements identity with the JDK
cryptography providers. The root build script also contains an absolute Android Studio JDK path that
only resolves on one workstation.

A stack record that does not match the manifests cannot gate anything: a verifier cannot tell whether
a missing capability is a defect or a deferred choice.

## Decision

The following is the canonical stack for AegisMCP until a later decision supersedes it:

| Concern | Choice | Verified in |
|---|---|---|
| Language and runtime | Java 21 | `build.gradle.kts` (`options.release`) |
| Gateway transport | Netty 4.1.118 | `services/gateway/build.gradle.kts` |
| Serialization | Jackson 2.17.2 (databind, YAML) | module manifests |
| CLI parser | picocli 4.7.6 | `apps/cli/build.gradle.kts` |
| Logging | SLF4J 2.0.16, Logback 1.5.16 | module manifests |
| Unit and integration tests | JUnit 5.10.2 | module manifests |
| Build | Gradle 9.3.1 (Kotlin DSL) | `gradle/wrapper/gradle-wrapper.properties` |
| Console | React 19, TypeScript 5.7, Vite 6, Tailwind 3.4 | `apps/console/package.json` |
| Console tests | Vitest 3, Testing Library | `apps/console/package.json` |
| Console package manager | npm | `apps/console/package-lock.json` |

Deliberate deferrals:

- Identity validation uses the JDK X.509 and signature APIs. Bouncy Castle, Nimbus JOSE, and the
  SPIFFE SDK are adopted only when a task requires a capability the JDK cannot provide, and the
  dependency is recorded in the same change.
- Testcontainers and Playwright are not dependencies. A containerized or browser harness is adopted
  only when a phase gate requires it, with the image and browser versions pinned.
- Chronicle Queue and the LMAX Disruptor are not adopted. The audit ledger uses its current
  implementation until a measured latency requirement cannot be met otherwise.

Phase 0 removes the workstation-specific JDK path and makes the build reproducible from the wrapper
alone.

This decision supersedes the stack claims in `ADR-001-stack-selection.md` and `ADR-001-stack.md`.
Those files remain as history; neither is authoritative for the current stack.

## Consequences

- Verification compares behavior against libraries the repository actually resolves.
- Adding a stack component is a visible decision, not an implicit drift between the record and the
  manifests.
- The lucide-react icon dependency and other console libraries remain governed by `package.json`; this
  table lists the load-bearing choices, not every transitive package.
