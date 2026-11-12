# AegisMCP

A zero-trust reverse proxy that sits between AI agents and MCP servers, checking every JSON-RPC
tool call before it reaches the backend.

## Why this exists

An agent that can read a customer record, issue a refund, or run a shell command is useful. The
question that matters in production is not whether it *can*, but whether it *should* — for this
caller, right now, with this payload. Most MCP deployments answer that question with nothing.

AegisMCP puts a policy layer between the agent and the tool, and keeps a record of every decision.

## What it does

- **Intercepts MCP traffic** — JSON-RPC over HTTP/SSE, WebSocket, and stdio
- **Policy as code** — declarative rules compiled into an in-memory AST, resolving to `allow`,
  `block`, or `require-approval`
- **Tool-chaining detection** — stateful analysis of call sequences rather than single requests in
  isolation
- **Velocity circuit breaking** — an agent that suddenly calls a tool forty times in a minute gets
  stopped, not rate-limited politely
- **DLP scrubbing** — credential and PII detection on the way out, using entropy scanning, Luhn
  validation, and path, SQL, and command-injection heuristics
- **Human-in-the-loop approvals** — via Slack, email, or the console, with fail-closed timeouts
- **Tamper-evident audit ledger** — SHA-256 hash chaining with Merkle verification and exportable
  compliance reports
- **Kill switch** — session quarantine that stops an agent without taking the gateway down

## Architecture

Gradle multi-module project, Java 21, Netty 4.1.

```
services/gateway     the proxy: codec, policy, dlp, anomaly, approval, audit, killswitch, compliance
apps/cli             operator CLI
apps/console         review and approval console
tests/e2e            end-to-end coverage across transports
```

Inside the gateway, each concern is its own package — `codec`, `proxy`, `identity`, `policy`,
`validation`, `dlp`, `anomaly`, `approval`, `audit`, `killswitch`, `compliance` — so a policy
decision never reaches into transport code, and the audit writer is not entangled with the proxy.

## Build and run

Requires JDK 21.

```bash
./gradlew build                 # compile and test every module
./gradlew test                  # unit tests (JUnit 5)
./gradlew :services:gateway:run # start the gateway
```

Gateway configuration is YAML, parsed with Jackson's YAML data format.

## Design decisions

**Fail closed.** A timeout on an approval request is a denial, not a pass. An unreachable policy
engine is a denial. The failure mode of a security component should never be "allow".

**Few dependencies.** Netty, Jackson, SLF4J, Logback. No web framework, no DI container. The
security-critical path stays readable.

**The audit log is a product feature, not logging.** Entries are chained and verifiable, because
"we think it was allowed" is not an answer an auditor accepts.

## Status

Active development. The gateway, CLI, and console build and test cleanly; transports are covered by
the e2e suite.
