# AegisMCP

A zero-trust reverse proxy that sits between AI agents and Model Context Protocol servers, checking
every JSON-RPC tool call before it reaches the backend.

## Why this exists

An agent that can read a customer record, issue a refund, or run a shell command is useful. The
question that matters in production is not whether it *can*, but whether it *should* — for this
caller, right now, with this payload. Most MCP deployments answer that question with nothing.

AegisMCP puts a policy layer between the agent and the tool, and keeps a record of every decision.

## What it does

- **Intercepts MCP traffic** — JSON-RPC over HTTP, with stdio wrapping in the developer CLI
- **Policy as code** — declarative rules compiled into an in-memory AST, resolving to `allow`,
  `block`, or `require-approval`
- **Tool-chaining detection** — stateful analysis of call sequences rather than single requests in
  isolation
- **Velocity circuit breaking** — an agent that suddenly calls a tool forty times in a minute gets
  stopped, not rate-limited politely
- **DLP scrubbing** — credential and PII detection on the way out, using entropy scanning, Luhn
  validation, and path, SQL, and command-injection heuristics
- **Human-in-the-loop approvals** — suspended calls with fail-closed timeouts, decided through the
  console or the management API
- **Tamper-evident audit ledger** — SHA-256 hash chaining with Merkle verification and exportable
  compliance reports
- **Kill switch** — session or tool quarantine that stops an agent without taking the gateway down

The console gives security teams a live traffic inspector, approval queue, policy manager, audit
explorer, and compliance export in one place.

## Architecture

Gradle multi-module project, Java 21, Netty 4.1.

```text
services/gateway   the proxy: codec, proxy, identity, policy, validation, dlp,
                   anomaly, approval, audit, killswitch, compliance
apps/cli           aegis-cli developer and operator tool
apps/console       React security console
tests/e2e          black-box artifact harness and contract conformance tests
contracts          interface contracts, one file per C-###
assets             brand source files and the ledger
infra              container and deployment assets
docs               specification submodule (aegismcp-docs)
```

Inside the gateway, each concern is its own package, so a policy decision never reaches into transport
code and the audit writer is not entangled with the proxy.

## Build and run

Requires JDK 21. The console requires Node.js and npm.

```bash
./gradlew build                    # compile and test every module
./gradlew :services:gateway:run    # start the gateway
./gradlew :apps:cli:run --args="--help"
cd apps/console && npm ci && npm test && npm run build
```

The specification lives in the `docs` submodule at [`docs/AegisMCP/`](docs/AegisMCP/). Interfaces live
in [`contracts/`](contracts/), and the build rules live in [`AGENTS.md`](AGENTS.md).

## Status

Active development, not production-ready. The security modules, CLI, and console have unit and
component coverage, but the bootable gateway does not yet assemble the enforcement pipeline: a request
to `POST /mcp/v1/rpc` currently returns a service banner instead of proxying through identity, policy,
DLP, anomaly, approval, and validation. The live inspector stream, verified management identity, and
the console-to-gateway connection are also outstanding. Integration recovery is Phase 4 of the
roadmap, and no phase gate is green until the packaged artifact enforces its contracts.

## Design decisions

**Fail closed.** A timeout on an approval request is a denial, not a pass. An unreachable policy
engine is a denial. The failure mode of a security component should never be "allow".

**Few dependencies.** Netty, Jackson, SLF4J, Logback. No web framework, no DI container. The
security-critical path stays readable. See [`.decisions/`](.decisions/).

**The audit log is a product feature, not logging.** Entries are chained and verifiable, because
"we think it was allowed" is not an answer an auditor accepts.

## License

MIT. See [LICENSE](LICENSE).
