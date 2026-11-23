# syntax=docker/dockerfile:1
# Gateway image. The build context is the repository root, so the wrapper, settings, and module
# manifests resolve exactly as they do in CI (infra/AGENTS.md). Anchors: NFR-020, NFR-021, NFR-028.

# Build stage
FROM eclipse-temurin:21-jdk-alpine AS builder

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

# Runtime stage
FROM eclipse-temurin:21-jre-alpine AS runner

# Non-root user for principle of least privilege (NFR-020, NFR-027)
RUN addgroup -S aegis && adduser -S aegis -G aegis -h /app

WORKDIR /app

COPY --from=builder --chown=aegis:aegis /app/services/gateway/build/install/gateway /app

USER aegis

# Documented listener: the gateway reads AEGIS_GATEWAY_HOST/AEGIS_GATEWAY_PORT and defaults to
# 8443 (C-001, user-flow.md).
EXPOSE 8443

ENV AEGIS_GATEWAY_HOST=0.0.0.0 \
    AEGIS_GATEWAY_PORT=8443

ENTRYPOINT ["/app/bin/gateway"]
