---
name: Phase
about: One roadmap phase and its gate
title: ""
labels: "phase"
assignees: ""
---

Roadmap phase:
Target:

## Outcome

-

## Specification Slice

- Features:
- Screens:
- Schemas:
- Contracts:
- Telemetry:
- NFRs:
- Monetization:

## Gate

The gate is a `verify` task, parented here and blocked by every other task in the phase. This phase
closes when the gate passes:
- All child tasks closed and unit tests pass
- Integration and acceptance tests pass against the contracts and criteria
- All declared screen states verified (empty, loading, error, success)
- Schema constraints and migrations verified
- Declared telemetry events (`EVT-###`) verified with payload validation
- Quantitative NFR targets verified (latency budgets, security, auth standards)
