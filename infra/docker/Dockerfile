# syntax=docker/dockerfile:1
# Build stage
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# Copy gradle wrapper and configurations
COPY gradlew gradlew.bat ./
COPY gradle gradle
COPY settings.gradle.kts build.gradle.kts ./
COPY services/gateway/build.gradle.kts services/gateway/

# Copy gateway source code
COPY services/gateway/src services/gateway/src

# Build production distribution
RUN ./gradlew :services:gateway:installDist --no-daemon -x test

# Runtime stage
FROM eclipse-temurin:21-jre-alpine AS runner

WORKDIR /app

# Non-root user for principle of least privilege (NFR-020, NFR-027)
RUN addgroup -S aegis && adduser -S aegis -G aegis

COPY --from=builder --chown=aegis:aegis /app/services/gateway/build/install/gateway /app

USER aegis

EXPOSE 8443

ENV AEGIS_GATEWAY_HOST=0.0.0.0 \
    AEGIS_GATEWAY_PORT=8443

ENTRYPOINT ["/app/bin/gateway"]
