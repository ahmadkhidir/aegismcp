# Contracts

One entry per interface. `Frozen` means both sides agree; `Implemented` means it shipped and
conforms. A change after `Frozen` is a `change-request` issue and a PR that updates both sides.

## Entry template

```text
### C-###: <METHOD> <path>
Status: Frozen | Implemented | Frozen (revision N)
Auth: <who may call it, and how>
Request: <field: type, ...>
Response <code>: <field: type, ...>
Errors: <code (meaning), ...>
```

---

### C-001: POST /mcp/v1/rpc
Status: Implemented
Auth: Agent workload via SPIFFE mTLS (X.509 SVID) or Bearer JWT (`Authorization: Bearer <token>`)
Request: JSON-RPC 2.0 object `{"jsonrpc": "2.0", "id": string|number, "method": string, "params": object}`
Response 200: JSON-RPC 2.0 object `{"jsonrpc": "2.0", "id": string|number, "result": object}`
Errors:
- 401 Unauthorized: Invalid or missing cryptographic agent credential (`-32000 Authentication Failed`)
- 403 Forbidden: Declarative policy violation or unauthorized tool execution (`-32001 Policy Violation`)
- 408 Request Timeout: Suspended approval timeout elapsed (`-32002 Approval Timed Out`)
- 429 Too Many Requests: Token bucket rate limit exceeded (`-32003 Rate Limited`)
- 502 Bad Gateway: Upstream MCP server unreachable or unhealthy (`-32004 Upstream Unavailable`)

### C-002: GET /api/v1/inspector/events
Status: Implemented
Auth: Console user or monitoring service via Session Cookie or Bearer API token
Request: HTTP GET query params `?agentId=string&minSeverity=string&limit=number`
Response 200: Server-Sent Events (`text/event-stream`) streaming `{"eventId": string, "timestamp": string, "agentId": string, "toolName": string, "verdict": "ALLOWED"|"BLOCKED"|"PENDING_APPROVAL", "latencyMs": number, "payloadSummary": string}`
Errors:
- 401 Unauthorized: Missing or invalid administrator token
- 403 Forbidden: Insufficient role permissions (`viewer` or `admin` required)

### C-003: GET /api/v1/approvals
Status: Implemented
Auth: Console operator via Bearer Token (`admin` or `operator` role)
Request: HTTP GET query params `?status=pending|approved|rejected|timed_out`
Response 200: `{"tickets": [{"id": string, "agentId": string, "toolName": string, "arguments": object, "riskScore": number, "status": string, "requestedAt": string, "expiresAt": string}]}`
Errors:
- 401 Unauthorized: Missing or invalid token

### C-004: POST /api/v1/approvals/{id}/decision
Status: Implemented
Auth: Console operator via Bearer Token (`admin` or `operator` role)
Request: `{"decision": "APPROVE"|"REJECT", "reviewer": string, "reason": string}`
Response 200: `{"ticketId": string, "status": "APPROVED"|"REJECTED", "processedAt": string}`
Errors:
- 400 Bad Request: Invalid decision payload or ticket already resolved
- 401 Unauthorized: Missing administrator credentials
- 404 Not Found: Approval ticket ID does not exist or expired

### C-005: GET /api/v1/policies
Status: Implemented
Auth: Console user or automated CI/CD pipeline via Bearer Token
Request: HTTP GET query params `?status=active|draft|archived`
Response 200: `{"policies": [{"id": string, "name": string, "version": string, "rawYaml": string, "status": string, "gitCommitHash": string, "createdAt": string}]}`
Errors:
- 401 Unauthorized: Missing authentication

### C-006: POST /api/v1/policies
Status: Implemented
Auth: Console administrator or CI/CD GitOps service account via Bearer Token (`admin` role)
Request: `{"name": string, "version": string, "rawYaml": string, "gitCommitHash": string}`
Response 201: `{"id": string, "name": string, "version": string, "status": "active", "createdAt": string}`
Errors:
- 400 Bad Request: Syntax error in YAML or invalid AST policy rules
- 401 Unauthorized: Missing authentication
- 403 Forbidden: Insufficient permissions to publish policy

### C-007: GET /api/v1/audit/verify
Status: Implemented
Auth: Auditor or Security Officer via Bearer Token (`auditor` or `admin` role)
Request: HTTP GET query params `?fromBlock=number&toBlock=number`
Response 200: `{"valid": boolean, "checkedBlocks": number, "merkleRoot": string, "latestBlockHash": string, "brokenAtBlock": number|null}`
Errors:
- 400 Bad Request: Invalid block range
- 401 Unauthorized: Missing authentication

### C-008: POST /api/v1/emergency/kill
Status: Implemented
Auth: Operator or Administrator via Bearer Token (`admin` role)
Request: `{"targetType": "global"|"agent"|"tool"|"server", "targetId": string, "reason": string}`
Response 200: `{"status": "QUARANTINED"|"SEVERED"|"ACTIVE", "affectedSessions": number, "timestamp": string}`
Errors:
- 400 Bad Request: Invalid target type or missing target ID
- 401 Unauthorized: Missing authentication
- 403 Forbidden: Insufficient permissions to trigger emergency kill-switch

### C-009: GET /api/v1/system/status
Status: Implemented
Auth: Console user or monitoring service via Session Cookie or Bearer API token
Request: empty
Response 200: `{"status": "NORMAL"|"ELEVATED"|"LOCKDOWN", "activeConnections": number, "totalRequests24h": number, "blockedViolations24h": number, "pendingApprovals": number}`
Errors:
- 401 Unauthorized: Missing authentication

### C-010: GET /api/v1/metrics/summary
Status: Implemented
Auth: Console user or monitoring service via Session Cookie or Bearer API token
Request: empty
Response 200: `{"activeAgents": number, "toolCalls24h": number, "blockedViolations24h": number, "pendingApprovals": number, "uptimeSeconds": number}`
Errors:
- 401 Unauthorized: Missing authentication

### C-011: POST /api/v1/compliance/export
Status: Implemented
Auth: Compliance Officer or Security Administrator via Bearer Token (`auditor` or `admin` role)
Request: `{"framework": "EU_AI_ACT"|"SOC2_TYPE2", "format": "JSON"|"CSV", "agentId": string (optional), "from": string (optional, ISO-8601), "to": string (optional, ISO-8601)}`
Response 200: `{"reportId": string, "framework": string, "status": "COMPLETED", "generatedAt": string, "recordCount": number, "violationsCount": number, "approvalsCount": number, "merkleRoot": string, "signature": string, "content": string}`
Errors:
- 400 Bad Request: Invalid framework or date range
- 401 Unauthorized: Missing authentication
- 403 Forbidden: Insufficient auditor permissions
- 409 Conflict: Cryptographic hash chain broken or integrity compromised

### C-012: POST /api/v1/policies/simulate
Status: Implemented
Auth: Security Administrator or Operator via Bearer Token
Request: `{"agentId": string, "toolName": string, "arguments": object}`
Response 200: `{"verdict": "ALLOWED"|"BLOCKED"|"REQUIRE_APPROVAL", "ruleMatched": string, "violations": string[]}`
Errors:
- 400 Bad Request: Malformed JSON payload
- 401 Unauthorized: Missing authentication

### C-013: GET /api/v1/audit/records
Status: Implemented
Auth: Auditor or Security Administrator via Bearer Token (`auditor` or `admin` role)
Request: HTTP GET query params `?agentId=string&minSeverity=string&decision=string&limit=number&offset=number`
Response 200: `{"records": [{"index": number, "blockHash": string, "parentHash": string, "agentId": string, "toolName": string, "decision": string, "redactionCount": number, "latencyMs": number, "timestamp": string}], "total": number}`
Errors:
- 401 Unauthorized: Missing authentication
- 403 Forbidden: Insufficient role permissions
