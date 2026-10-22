# ADR-001: Technology stack and platform choices

- Status: Accepted
- Date: 2026-10-22

## Context

The specification defines the architectural, functional, and performance requirements for AegisMCP. The technology stack, runtime, frameworks, and tooling were selected to fulfill these constraints and quality targets.

## Decision

The following stack and platform choices are adopted:

| Concern | Choice | Note |
|---|---|---|
| Core Gateway | Java 21, Netty 4.1, Loom Virtual Threads | Sub-5ms P99 overhead (`NFR-001`), 50k sessions (`NFR-002`) |
| Build Tool | Gradle 8.7 (Kotlin DSL) | Hermetic multi-project builds (`gradlew`) |
| Cryptography & Identity | Bouncy Castle, SPIFFE Java SDK | X.509 SVID validation & hardware-accelerated TLS 1.3 |
| Console Frontend | React 19, TypeScript, Vite, Tailwind CSS | Decoupled SPA for security operations center |
| E2E & Verification | JUnit 5, Testcontainers, Playwright | Containerized black-box test harness simulating MCP agents |

## Consequences

- Toolchains and package manifests are bootstrapped and pinned during Phase 0 (Foundation).
- Commands defined for build, test, and verification are wired into repo scripts/Makefile and CI/CD.
- Code written in subsequent roadmap phases must conform to these platform choices.
