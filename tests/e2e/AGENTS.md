# tests/e2e

Root `AGENTS.md` § Verification owns the verifier's mandate. This file adds only how to run this
harness.

## Scope

This directory and its subdirectories. Write only test files and test configuration; feature code is read-only.

## Harness

- Start the app the documented way before the suite.
- Seed and reset data the way this harness expects.
- Run the suite with the commands below.
- Report failures with file/line and expected vs actual; never fix feature code.

## Commands

- Run end-to-end integration and verification suite: `./gradlew :tests:e2e:test`
- Run performance latency benchmark: `./gradlew :tests:e2e:test --tests "dev.aegismcp.e2e.Phase1PerformanceLatencyBenchmarkTest"`

## Local Definition of Done

- The suite runs from a clean checkout.
- Seed and reset work.
- Failures carry file/line and expected vs actual.
