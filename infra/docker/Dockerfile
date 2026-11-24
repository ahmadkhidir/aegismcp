# syntax=docker/dockerfile:1
# Gateway image. The build context is the repository root, so the wrapper, settings, and module
# manifests resolve exactly as they do in CI (infra/AGENTS.md). Anchors: NFR-020, NFR-021, NFR-028.
#
# Build through infra/docker/build-image (or build-image.ps1): it supplies the OCI revision and
# version, writes the SBOM, and fails on a CRITICAL/HIGH finding before an image is released. A
# bare `docker build` produces the same image but skips the supply-chain gate.

# Build stage. Pinned by version tag and multi-arch index digest so a retag cannot change the
# bytes this repository compiles against (NFR-028).
FROM eclipse-temurin:21-jdk-alpine@sha256:c07bb82e004a166b5d3d63b84ad70e2e822f228505e2e0c0b8dfdc2890d22f13 AS builder

WORKDIR /app

# Copy the wrapper and its distribution metadata first so dependency resolution stays cached
# when only sources change.
COPY gradlew ./
COPY gradle gradle

# The wrapper arrives with the line endings the host checkout gave it. Normalize the script and
# mark it executable before /bin/sh reads its shebang (NFR-028, ADR-002).
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew

# Copy the root build definitions and one manifest per project that settings.gradle.kts includes.
# Gradle 9 refuses to configure a project whose directory is absent, and the gateway distribution
# needs the whole build graph configured even though only the gateway contributes sources.
COPY settings.gradle.kts build.gradle.kts ./
COPY services/gateway/build.gradle.kts services/gateway/
COPY apps/cli/build.gradle.kts apps/cli/
COPY tests/e2e/build.gradle.kts tests/e2e/

# Copy gateway source code
COPY services/gateway/src services/gateway/src

# Build production distribution
RUN ./gradlew :services:gateway:installDist --no-daemon -x test

# Runtime stage. Same pinning rule as the builder (NFR-028).
FROM eclipse-temurin:21-jre-alpine@sha256:5d7689f47d670aca766b9503a70bccc2d73b4eb9221ae8f714ae958313c4ce70 AS runner

# OCI metadata. The revision and version are configuration the build script derives from the
# checkout; no secret, token, or host path reaches a label (NFR-023, NFR-028).
ARG BUILD_REVISION=unknown
ARG BUILD_VERSION=unknown
LABEL org.opencontainers.image.title="AegisMCP Gateway" \
      org.opencontainers.image.description="Zero-trust MCP gateway: identity, policy, validation, DLP, approval, and audit." \
      org.opencontainers.image.source="https://github.com/ahmadkhidir/aegismcp" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.licenses="MIT"

# Least privilege: one fixed numeric uid/gid, no login shell, no package-manager upgrade at
# runtime (NFR-020, NFR-027). The numeric USER keeps the identity stable across base image
# revisions that renumber their own accounts.
RUN addgroup -g 10001 -S aegis \
 && adduser -u 10001 -S -D -G aegis -h /app -s /sbin/nologin aegis

WORKDIR /app

COPY --from=builder --chown=10001:10001 /app/services/gateway/build/install/gateway /app

# Liveness probe. It reads the same port and TLS switches the gateway reads, so it keeps
# targeting GET /health (C-022) whether the listener serves cleartext in a local stack or TLS in
# a production deployment (NFR-021).
# A Windows checkout may hand the context a CRLF script; normalize it before /bin/sh reads the
# shebang, exactly as the wrapper step does for gradlew (NFR-028, ADR-002).
COPY infra/docker/healthcheck.sh /usr/local/bin/aegis-healthcheck
RUN sed -i 's/\r$//' /usr/local/bin/aegis-healthcheck \
 && chmod 0755 /usr/local/bin/aegis-healthcheck

USER 10001:10001

# Documented listener: the gateway reads AEGIS_GATEWAY_HOST/AEGIS_GATEWAY_PORT and defaults to
# 8443 (C-001, user-flow.md).
EXPOSE 8443

ENV AEGIS_GATEWAY_HOST=0.0.0.0 \
    AEGIS_GATEWAY_PORT=8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/aegis-healthcheck"]

# Exec form so SIGTERM reaches the JVM and the release's termination window drains in-flight
# connections (infra/AGENTS.md "Runtime contract").
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/bin/gateway"]
