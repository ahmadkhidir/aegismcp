# ADR-001: Technology Stack Selection

- Status: Accepted
- Date: 2026-10-21

## Context

AegisMCP is an enterprise-grade Zero-Trust reverse proxy and security firewall designed to intercept, policy, and audit Model Context Protocol (MCP) tool calls between AI agents and backend systems.
The architecture demands ultra-low latency overhead (sub-5ms P99 per `NFR-001`), high concurrency handling (50,000 concurrent streaming JSON-RPC sessions per `NFR-002`), cryptographic SPIFFE/SPIRE mTLS identity validation, streaming AST policy enforcement, and audit immutability. Additionally, the project is structured to showcase senior-level Java systems engineering alongside a decoupled modern frontend dashboard.

## Decision

We adopt the following technology stack across the project areas:

1. **Core Gateway Runtime (`services/gateway`)**:
   - **Java 21 (LTS)** leveraging Project Loom Virtual Threads (`java.lang.Thread.ofVirtual()`) for lightweight concurrent request processing.
   - **Netty 4.1**: Non-blocking asynchronous network transport with zero-copy ByteBuf allocation and streaming JSON-RPC 2.0 framing.
   - **Jackson 2.17 (Smile & Streaming API)**: Zero-copy JSON parsing and token-stream AST analysis.
   - **SPIFFE Java SDK & Bouncy Castle**: Hardware-accelerated TLS 1.3 cryptographic primitives and SPIRE X.509 SVID validation.
   - **Chronicle Queue / Disruptor**: Lock-free LMAX disruptor ring buffer for sub-millisecond tamper-evident audit logging (`NFR-004`).

2. **Build & Tooling**:
   - **Gradle 8.7 (Kotlin DSL)**: Multi-project build configuration (`settings.gradle.kts`), build cache optimization, and reproducible hermetic compilation.

3. **Management Console (`apps/console`)**:
   - **React 19 + TypeScript 5.4 + Vite 5**: Decoupled Single Page Application (SPA) designed to compile to static assets with lightning-fast HMR.
   - **Tailwind CSS 3.4**: Consistent aesthetic styling matching the AegisMCP brand palette and dark-mode security operations center theme.
   - **Lucide Icons**: Standardized UI iconography.

4. **Infrastructure & Platform (`infra`)**:
   - **Docker & Docker Compose**: Hermetic multi-container local evaluation and reproducible integration environment.
   - **SPIRE / Envoy sidecar templates**: Production Kubernetes Helm chart blueprints for SPIFFE workload attestation.

5. **Testing Harness (`tests/e2e`)**:
   - **JUnit 5 + Testcontainers**: Automated end-to-end integration testing simulating MCP clients, mock MCP servers, and simulated attack vectors (prompt injection, SSRF, tool poisoning).
   - **Playwright**: Headless browser verification for human-in-the-loop approval workflows.

## Consequences

- High throughput with sub-5ms P99 latency overhead and minimal memory footprint.
- Strict architectural decoupling between the high-throughput Netty proxy core and the web UI.
- Deterministic, reproducible builds and tests runnable across developer workstations and CI environments.
