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

## Quick start

Requires JDK 21, Node.js, Docker, and GNU Make. `make help` lists every target.

```bash
make setup     # generate the local OIDC credentials and the untracked console env
make up        # start Keycloak and the packaged gateway, then provision the role users
make console   # run the console at http://localhost:3000
make smoke     # real login, gateway token validation, role-based access
make down      # stop the stack
```

`make dev` runs `make up` followed by `make console`. The local topology is
[`infra/compose/compose.yaml`](infra/compose/compose.yaml); credentials are generated into the
gitignored `infra/compose/.env`, never committed.

### Local login

| User | Role | Password variable |
|---|---|---|
| `aegis-admin` | `admin` | `AEGIS_OIDC_ADMIN_USER_PASSWORD` |
| `aegis-operator` | `operator` | `AEGIS_OIDC_OPERATOR_USER_PASSWORD` |
| `aegis-auditor` | `auditor` | `AEGIS_OIDC_AUDITOR_USER_PASSWORD` |
| `aegis-viewer` | `viewer` | `AEGIS_OIDC_VIEWER_USER_PASSWORD` |

Passwords are in the gitignored `infra/compose/.env`.

## Build and run

Requires JDK 21. The console requires Node.js and npm.

```bash
./gradlew build                    # compile and test every module
./gradlew :services:gateway:run    # start the gateway
./gradlew :apps:cli:run --args="--help"
cd apps/console && npm ci && npm test && npm run build
```

The same commands are wrapped by `make build`, `make test`, `make test-unit`, `make test-console`,
`make e2e`, `make boot`, and `make contracts`.

The specification lives in the `docs` submodule at [`docs/AegisMCP/`](docs/AegisMCP/). Interfaces live
in [`contracts/`](contracts/), and the build rules live in [`AGENTS.md`](AGENTS.md).

## Status

Active development; Phase 4 integration hardening is in progress. The packaged gateway now assembles
identity, validation, policy, approval, anomaly, upstream, DLP, and audit, and the console runs on a
real Keycloak provider with no mock data. The artifact conformance suite still exposes open contract
defects (kill/release control plane, violation feed, async export, DLP reporting, the 20 MB ceiling,
and `resources/read` follow-ups), and NFR-001 added latency is not met. Not production-ready.

## Design decisions

**Fail closed.** A timeout on an approval request is a denial, not a pass. An unreachable policy
engine is a denial. The failure mode of a security component should never be "allow".

**Few dependencies.** Netty, Jackson, SLF4J, Logback. No web framework, no DI container. The
security-critical path stays readable. See [`.decisions/`](.decisions/).

**The audit log is a product feature, not logging.** Entries are chained and verifiable, because
"we think it was allowed" is not an answer an auditor accepts.

## License

MIT. See [LICENSE](LICENSE).
