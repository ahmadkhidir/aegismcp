# Contracts

One file per interface. `Draft` is under discussion and not dispatchable. `Frozen` means both sides
agree; implementing tasks may dispatch. A contract becomes `Implemented` only when its conformance
test passes against the packaged artifact in CI. A change after `Frozen` is a `change-request` issue
and a PR that updates both sides.

| Contract | Title | Owner | Status | Conformance test |
|---|---|---|---|---|
| [C-001](C-001.md) | JSON-RPC proxy | services/gateway | Frozen | C001RpcProxyContractTest#proxiesAllowedToolCallAndPreservesRequestId |
| [C-002](C-002.md) | Live traffic and approval event stream | services/gateway | Frozen | C002TrafficStreamContractTest#streamsTrafficEventsWithHeartbeat |
| [C-003](C-003.md) | Pending approval queue | services/gateway | Frozen | C003PendingApprovalsContractTest#listsPendingTicketsOrderedByExpiry |
| [C-004](C-004.md) | Approve suspended tool call | services/gateway | Frozen | C004ApproveDecisionContractTest#approvesPendingTicketAndResumesExecution |
| [C-005](C-005.md) | Policy catalogue | services/gateway | Frozen | C005PolicyListContractTest#listsPoliciesFilteredByStatus |
| [C-006](C-006.md) | Publish policy version | services/gateway | Frozen | C006PolicyPublishContractTest#publishesDraftPolicyVersion |
| [C-008](C-008.md) | Emergency kill switch | services/gateway | Frozen | C008EmergencyKillContractTest#quarantinesAgentAndSeversSessions |
| [C-009](C-009.md) | Fleet system status | services/gateway | Frozen | C009SystemStatusContractTest#reportsNormalFleetStatus |
| [C-010](C-010.md) | Metrics summary | services/gateway | Frozen | C010MetricsSummaryContractTest#reportsTwentyFourHourMetricSummary |
| [C-011](C-011.md) | Compliance report export | services/gateway | Frozen | C011ComplianceExportContractTest#exportsSignedEuAiActJsonReport |
| [C-012](C-012.md) | Policy simulation | services/gateway | Frozen | C012PolicySimulationContractTest#simulatesAllowedToolInvocation |
| [C-013](C-013.md) | Audit record query | services/gateway | Frozen | C013AuditRecordsContractTest#queriesAuditRecordsByDecision |
| [C-014](C-014.md) | Reject suspended tool call | services/gateway | Frozen | C014ApprovalRejectionContractTest#rejectsPendingTicketWithReason |
| [C-015](C-015.md) | Ledger integrity | services/gateway | Frozen | C015AuditIntegrityContractTest#reportsVerifiedLedgerIntegrity |
| [C-016](C-016.md) | Security violation feed | services/gateway | Frozen | C016ViolationFeedContractTest#listsRecentSecurityViolations |
| [C-017](C-017.md) | Active policy | services/gateway | Frozen | C017ActivePolicyContractTest#returnsActivePolicyDocument |
| [C-018](C-018.md) | Deploy active policy | services/gateway | Frozen | C018PolicyDeploymentContractTest#deploysActivePolicyDocument |
| [C-019](C-019.md) | Approval history | services/gateway | Frozen | C019ApprovalHistoryContractTest#listsRejectedApprovalHistory |
| [C-020](C-020.md) | Metrics timeseries | services/gateway | Frozen | C020MetricsTimeseriesContractTest#returnsTwentyFourHourMetricTimeseries |
| [C-021](C-021.md) | Emergency release | services/gateway | Frozen | C021EmergencyReleaseContractTest#releasesQuarantinedTargetAndLiftsLockdown |
| [C-022](C-022.md) | Health probe | services/gateway | Frozen | C022HealthContractTest#answersLivenessProbeWhileDependenciesAreDown |
| [C-023](C-023.md) | Readiness probe | services/gateway | Frozen | C023ReadinessContractTest#reportsDependencyHealthAndRefusesTrafficWhenDown |

C-007 was retired in the endpoint reconciliation pass. It duplicated the ledger-integrity resource now
defined once by C-015. Retired identifiers are not reused.
