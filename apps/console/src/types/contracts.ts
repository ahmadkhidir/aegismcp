/**
 * Specification Anchors: FEAT-008, FEAT-011, FEAT-012, C-002..C-020
 * Frozen gateway payload shapes consumed by the console.
 *
 * These mirror `contracts/C-###.md`. A new gateway field belongs here first;
 * screens never redeclare a payload shape of their own.
 */

export type ThreatLevel = 'NORMAL' | 'ELEVATED' | 'LOCKDOWN';

/** C-002: live traffic stream */
export type EventDecision = 'ALLOWED' | 'BLOCKED' | 'PENDING_APPROVAL';

export type RedactionCategory = 'SECRET' | 'PII';

export interface Redaction {
  category: RedactionCategory;
  type: string;
  count: number;
}

export interface InspectorEvent {
  eventId: string;
  timestamp: string;
  agentId: string;
  toolName: string;
  arguments: Record<string, unknown>;
  decision: EventDecision;
  latencyMs: number;
  matchedRuleIds: string[];
  redactions: Redaction[];
}

export interface ApprovalStreamEvent {
  ticketId: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  expiresAt: string;
}

export interface SystemStreamEvent {
  status: ThreatLevel;
  pendingApprovals: number;
}

export type StreamStatus = 'connecting' | 'connected' | 'reconnecting' | 'disconnected';

/** C-003: pending approval queue */
export interface ApprovalTicket {
  id: string;
  agentId: string;
  toolName: string;
  argumentsPayload: string;
  triggerPolicyId: string;
  agentIntent: string | null;
  status: 'pending';
  createdAt: string;
  expiresAt: string;
}

export interface ApprovalsResponse {
  tickets: ApprovalTicket[];
}

/** C-019: approval history */
export type ApprovalHistoryStatus = 'approved' | 'rejected' | 'expired';

export interface ApprovalHistoryTicket {
  id: string;
  agentId: string;
  toolName: string;
  argumentsPayload: string;
  triggerPolicyId: string;
  status: ApprovalHistoryStatus;
  createdAt: string;
  expiresAt: string;
  reviewedBy: string | null;
  rejectionReason: string | null;
  processedAt: string | null;
}

export interface ApprovalHistoryResponse {
  tickets: ApprovalHistoryTicket[];
  total: number;
}

/** C-004: approve a suspended tool call */
export interface ApprovalDecisionResponse {
  ticketId: string;
  status: 'approved';
  reviewedBy: string;
  processedAt: string;
}

/** C-014: reject a suspended tool call */
export interface ApprovalRejectionRequest {
  reason: string;
}

export interface ApprovalRejectionResponse {
  ticketId: string;
  status: 'rejected';
  reviewedBy: string;
  rejectionReason: string;
  processedAt: string;
}

/** C-005 and C-017: policy catalogue and active policy */
export interface PolicyRecord {
  id: string;
  name: string;
  version: string;
  rawYaml: string;
  status: 'active' | 'draft' | 'archived';
  gitCommitHash: string | null;
  createdAt: string;
}

export interface PoliciesResponse {
  policies: PolicyRecord[];
}

/** C-006: publish a policy version */
export interface CreatePolicyRequest {
  name: string;
  version: string;
  rawYaml: string;
  gitCommitHash?: string;
}

export interface CreatePolicyResponse {
  id: string;
  name: string;
  version: string;
  status: 'draft';
  createdAt: string;
}

/** C-018: activate a policy version */
export interface ActivatePolicyRequest {
  version: string;
  baseVersionId: string;
  rawYaml: string;
}

/** C-015: most recent completed ledger verification */
export interface AuditIntegrityResponse {
  valid: boolean;
  totalVerifiedBlocks: number;
  lastVerifiedAt: string;
}

/** C-013: audit record query */
export type AuditDecision = 'allow' | 'block' | 'require_approval';

export interface AuditRecordItem {
  blockIndex: number;
  blockHash: string;
  parentHash: string;
  agentId: string;
  toolName: string;
  argumentsHash: string;
  decision: AuditDecision;
  redactionCount: number;
  latencyMs: number;
  timestamp: string;
  reviewedBy: string | null;
}

export interface AuditRecordsResponse {
  records: AuditRecordItem[];
  total: number;
}

/** C-011: compliance report export */
export type ComplianceFramework = 'EU_AI_ACT' | 'SOC2_TYPE2';
export type ComplianceFormat = 'JSON' | 'CSV' | 'PDF';

export interface ComplianceExportRequest {
  framework: ComplianceFramework;
  format: ComplianceFormat;
  agentId?: string;
  from: string;
  to: string;
}

export interface ComplianceExportResponse {
  reportId: string;
  framework: string;
  format: string;
  status: 'COMPLETED';
  generatedAt: string;
  recordCount: number;
  violationsCount: number;
  approvalsCount: number;
  merkleRoot: string;
  signature: string;
  content: string;
}

export interface ComplianceExportAcceptedResponse {
  reportId: string;
  status: 'GENERATING';
}

/** C-012: policy simulation */
export interface PolicySimulateRequest {
  agentId: string;
  toolName: string;
  arguments: Record<string, unknown>;
}

export interface PolicySimulateResponse {
  verdict: 'ALLOWED' | 'BLOCKED' | 'REQUIRE_APPROVAL';
  ruleMatched: string | null;
  violations: string[];
}

/** C-008: emergency kill switch */
export interface EmergencyKillRequest {
  targetType: 'session' | 'agent' | 'server' | 'global';
  targetId?: string;
  reason?: string;
  secondApprover?: string;
}

export interface EmergencyKillResponse {
  status: 'QUARANTINED' | 'SEVERED' | 'LOCKDOWN';
  affectedSessions: number;
  timestamp: string;
}

/** C-009: fleet system status */
export interface SystemStatusResponse {
  status: ThreatLevel;
  activeConnections: number;
  connectedNodes: number;
  totalRequests24h: number;
  blockedViolations24h: number;
  pendingApprovals: number;
}

/** C-010: metrics summary */
export interface MetricsSummaryResponse {
  activeAgents: number;
  toolCalls24h: number;
  blockedViolations24h: number;
  pendingApprovals: number;
  uptimeSeconds: number;
}

/** C-016: security violation feed */
export type ViolationType =
  | 'prompt_injection'
  | 'tool_chaining_anomaly'
  | 'schema_violation'
  | 'path_traversal'
  | 'unauthorized_tool'
  | 'rate_limit_exceeded';

export type ViolationSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityViolation {
  id: string;
  agentId: string;
  violationType: ViolationType;
  blockHash: string;
  severity: ViolationSeverity;
  details: string;
  createdAt: string;
}

export interface ViolationsResponse {
  violations: SecurityViolation[];
}

/** C-020: 24-hour metrics timeseries */
export interface MetricsTimeseriesBucket {
  bucketStart: string;
  toolCalls: number;
  blockedViolations: number;
}

export interface MetricsTimeseriesResponse {
  interval: 'HOUR';
  buckets: MetricsTimeseriesBucket[];
}
