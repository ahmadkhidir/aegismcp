# AegisMCP developer commands.
#
# The recipes run under cmd.exe on Windows and /bin/sh elsewhere. Every target is a thin wrapper
# over a command the repository already documents; no secret is embedded here.

ifeq ($(OS),Windows_NT)
GRADLE       := gradlew.bat
SHELL        := cmd.exe
.SHELLFLAGS  := /C
BOOT_CHECK   := powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify-artifact.ps1
CONTRACTS    := powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-contracts.ps1
IMAGE_BUILD  := powershell -NoProfile -ExecutionPolicy Bypass -File infra/docker/build-image.ps1
else
GRADLE       := ./gradlew
SHELL        := /bin/sh
BOOT_CHECK   := scripts/verify-artifact
CONTRACTS    := scripts/check-contracts
IMAGE_BUILD  := infra/docker/build-image
endif

COMPOSE := docker compose -f infra/compose/compose.yaml --env-file infra/compose/.env

.PHONY: help setup up down logs smoke console dev gateway cli build test test-unit test-console e2e boot contracts image docker clean

help:
	@echo AegisMCP - common commands
	@echo ---
	@echo   make setup        Generate local OIDC credentials and the console env
	@echo   make up           Start Keycloak and the gateway, then provision users
	@echo   make console      Run the console at http://localhost:3000
	@echo   make dev          make up, then make console
	@echo   make smoke        Real login, gateway token check, role access
	@echo   make down         Stop the local stack
	@echo   make logs         Follow gateway and Keycloak logs
	@echo ---
	@echo   make build        Build and test every module
	@echo   make test         Run the full test suite
	@echo   make test-unit    Gateway and CLI unit tests
	@echo   make test-console Console tests
	@echo   make e2e          Artifact and contract suite
	@echo   make boot         Boot the packaged gateway and check health
	@echo   make contracts    Validate the frozen contract set
	@echo ---
	@echo   make gateway      Run the gateway from your environment
	@echo   make cli          Print aegis-cli usage
	@echo   make image        Build the hardened image with SBOM and scan
	@echo   make docker       Build the plain local image
	@echo   make clean        Remove build outputs

setup:
	node infra/compose/bootstrap-oidc.mjs init
	@node -e "const fs=require('fs'); if(!fs.existsSync('apps/console/.env.local')) fs.copyFileSync('apps/console/.env.example','apps/console/.env.local')"

up: setup
	$(COMPOSE) up -d --wait
	node infra/compose/bootstrap-oidc.mjs provision

down:
	$(COMPOSE) down --remove-orphans

logs:
	$(COMPOSE) logs -f gateway keycloak

smoke:
	$(COMPOSE) --profile smoke run --rm oidc-smoke

console:
	@node -e "const fs=require('fs'); if(!fs.existsSync('apps/console/.env.local')) fs.copyFileSync('apps/console/.env.example','apps/console/.env.local')"
	@node -e "process.exit(require('fs').existsSync('apps/console/node_modules')?0:1)" || cd apps/console && npm ci
	cd apps/console && npm run dev

dev: up console

gateway:
	$(GRADLE) :services:gateway:run

cli:
	$(GRADLE) :apps:cli:run --args="--help"

build:
	$(GRADLE) build

test:
	$(GRADLE) test

test-unit:
	$(GRADLE) :services:gateway:test :apps:cli:test

test-console:
	cd apps/console && npm ci
	cd apps/console && npm test

e2e:
	$(GRADLE) :tests:e2e:test

boot:
	$(BOOT_CHECK)

contracts:
	$(CONTRACTS)

image:
	$(IMAGE_BUILD)

docker:
	docker build -f infra/docker/Dockerfile -t aegismcp-gateway:local .

clean:
	$(GRADLE) clean
	@node -e "require('fs').rmSync('apps/console/dist',{recursive:true,force:true})"
