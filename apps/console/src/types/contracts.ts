/**
 * Specification Anchors: FEAT-008, FEAT-011, FEAT-012, C-002, C-003, C-004, C-005, C-006, C-007, C-008, C-009, C-010, C-011, C-012, C-013
 * Contracts interface definitions for AegisMCP Security Console
 */

/** C-002: Live Traffic Inspector Event */
export type EventVerdict = 'ALLOWED' | 'BLOCKED' | 'PENDING_APPROVAL' | 'QUARANTINED';

export interface InspectorEvent {
  eventId: string;
  timestamp: string;
  agentId: string;
  toolName: string;
  verdict: EventVerdict;
  latencyMs: number;
  payloadSummary: string;
  // Extended details for right-drawer inspection
  rawRequest?: Record<string, unknown>;
  rawResponse?: Record<string, unknown>;
  matchedPolicyRule?: string;
  redactions?: Array<{
    field: string;
    type: 'SECRET_TOKEN' | 'API_KEY' | 'PII' | 'CREDENTIAL';
    maskedPreview: string;
  }>;
}

/** C-003: Approval Ticket */
export interface ApprovalTicket {
  id: string;
  agentId: string;
  toolName: string;
  arguments: Record<string, unknown>;
  riskScore: number;
  status: 'pending' | 'approved' | 'rejected' | 'timed_out';
  requestedAt: string;
  expiresAt: string;
  reason?: string;
  agentIntent?: string;
}

export interface ApprovalsResponse {
  tickets: ApprovalTicket[];
}

/** C-004: Approval Decision Request & Response */
export interface ApprovalDecisionRequest {
  decision: 'APPROVE' | 'REJECT';
  reviewer: string;
  reason: string;
}

export interface ApprovalDecisionResponse {
  ticketId: string;
  status: 'APPROVED' | 'REJECTED';
  processedAt: string;
}

/** C-005: Declarative Policy */
export interface PolicyRecord {
  id: string;
  name: string;
  version: string;
  rawYaml: string;
  status: 'active' | 'draft' | 'archived';
  gitCommitHash: string;
  createdAt: string;
  astRules?: Array<{
    ruleId: string;
    description: string;
    targetTools: string[];
    action: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL';
  }>;
}

export interface PoliciesResponse {
  policies: PolicyRecord[];
}

/** C-006: Create Policy Request & Response */
export interface CreatePolicyRequest {
  name: string;
  version: string;
  rawYaml: string;
  gitCommitHash: string;
}

export interface CreatePolicyResponse {
  id: string;
  name: string;
  version: string;
  status: 'active';
  createdAt: string;
}

/** C-007: Cryptographic Audit Verification */
export interface AuditVerifyResponse {
  valid: boolean;
  checkedBlocks: number;
  merkleRoot: string;
  latestBlockHash: string;
  brokenAtBlock: number | null;
}

export interface AuditRecordItem {
  index: number;
  blockHash: string;
  parentHash: string;
  agentId: string;
  toolName: string;
  decision: EventVerdict | string;
  redactionCount: number;
  latencyMs: number;
  timestamp: string;
  // Extended forensic verification fields
  prevHash?: string;
  approver?: string | null;
  signature?: string;
}

export type AuditRecord = AuditRecordItem;

export interface AuditRecordsResponse {
  records: AuditRecordItem[];
  total: number;
}

/** C-011: POST /api/v1/compliance/export */
export interface ComplianceExportRequest {
  framework: 'EU_AI_ACT' | 'SOC2_TYPE2';
  format: 'JSON' | 'CSV';
  agentId?: string;
  from?: string;
  to?: string;
}

export interface ComplianceExportResponse {
  reportId: string;
  framework: string;
  status: 'COMPLETED';
  generatedAt: string;
  recordCount: number;
  violationsCount: number;
  approvalsCount: number;
  merkleRoot: string;
  signature: string;
  content: string;
}

/** C-012: POST /api/v1/policies/simulate */
export interface PolicySimulateRequest {
  agentId: string;
  toolName: string;
  arguments: Record<string, unknown>;
}

export interface PolicySimulateResponse {
  verdict: 'ALLOWED' | 'BLOCKED' | 'REQUIRE_APPROVAL';
  ruleMatched: string;
  violations: string[];
}

/** C-008: Emergency Kill-Switch Request & Response */
export interface EmergencyKillRequest {
  targetType: 'global' | 'agent' | 'tool' | 'server';
  targetId: string;
  reason: string;
}

export interface EmergencyKillResponse {
  status: 'QUARANTINED' | 'SEVERED' | 'ACTIVE';
  affectedSessions: number;
  timestamp: string;
}

/** C-009: System Status */
export type ThreatLevel = 'NORMAL' | 'ELEVATED' | 'LOCKDOWN';

export interface SystemStatusResponse {
  status: ThreatLevel;
  activeConnections: number;
  totalRequests24h: number;
  blockedViolations24h: number;
  pendingApprovals: number;
}

/** C-010: Metrics Summary */
export interface MetricsSummaryResponse {
  activeAgents: number;
  toolCalls24h: number;
  blockedViolations24h: number;
  pendingApprovals: number;
  uptimeSeconds: number;
}
