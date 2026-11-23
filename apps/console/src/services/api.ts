/**
 * Specification Anchors: FEAT-008, FEAT-011, FEAT-012, C-002..C-020
 * Gateway adapter for the console. Every method either returns the frozen
 * contract payload or raises an ApiError; there is no fixture fallback.
 */

import {
  ApprovalsResponse,
  ApprovalDecisionResponse,
  ApprovalHistoryResponse,
  ApprovalHistoryStatus,
  ApprovalRejectionResponse,
  AuditIntegrityResponse,
  AuditRecordsResponse,
  ComplianceExportAcceptedResponse,
  ComplianceExportRequest,
  ComplianceExportResponse,
  CreatePolicyRequest,
  CreatePolicyResponse,
  EmergencyKillRequest,
  EmergencyKillResponse,
  InspectorEvent,
  MetricsSummaryResponse,
  MetricsTimeseriesResponse,
  PoliciesResponse,
  PolicyRecord,
  PolicySimulateRequest,
  PolicySimulateResponse,
  SecurityViolation,
  StreamStatus,
  SystemStatusResponse,
  ViolationSeverity,
  ViolationType,
  ActivatePolicyRequest,
} from '../types/contracts';
import { oidcService } from './oidc';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly brokenBlockIndex?: number;

  constructor(
    status: number,
    message: string,
    options: { code?: string; brokenBlockIndex?: number } = {}
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = options.code;
    this.brokenBlockIndex = options.brokenBlockIndex;
  }
}

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = oidcService.getAccessToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

interface ErrorBody {
  error?: string | { code?: string; message?: string };
  message?: string;
  detail?: string;
  brokenBlockIndex?: number;
}

function messageFromBody(body: ErrorBody, status: number): string {
  if (typeof body.error === 'string' && body.error.trim()) return body.error;
  if (body.error && typeof body.error === 'object' && body.error.message) return body.error.message;
  if (typeof body.message === 'string' && body.message.trim()) return body.message;
  if (typeof body.detail === 'string' && body.detail.trim()) return body.detail;
  return `The gateway returned HTTP ${status}.`;
}

async function raiseForResponse(response: Response): Promise<never> {
  let body: ErrorBody = {};
  try {
    const text = await response.text();
    if (text) body = JSON.parse(text) as ErrorBody;
  } catch {
    // A non-JSON error body still becomes a status-bearing ApiError below.
  }
  const code = typeof body.error === 'object' ? body.error?.code : undefined;
  throw new ApiError(response.status, messageFromBody(body, response.status), {
    code,
    brokenBlockIndex:
      typeof body.brokenBlockIndex === 'number' ? body.brokenBlockIndex : undefined,
  });
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: authHeaders({
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(init.headers as Record<string, string> | undefined),
      }),
    });
  } catch {
    throw new ApiError(0, 'The gateway could not be reached.');
  }

  if (!response.ok) {
    await raiseForResponse(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== '') search.set(key, String(value));
  });
  const serialized = search.toString();
  return serialized ? `?${serialized}` : '';
}

export interface TrafficStreamHandlers {
  onEvent: (event: InspectorEvent) => void;
  onApproval?: (event: { ticketId: string; status: string; expiresAt: string }) => void;
  onSystem?: (event: { status: SystemStatusResponse['status']; pendingApprovals: number }) => void;
  onStatus?: (status: StreamStatus) => void;
  onError?: (message: string) => void;
  onReconnected?: () => void;
}

interface SseFrame {
  event: string;
  data: string;
  id: string | null;
}

/** Splits one SSE frame into its named event, joined data lines, and id. */
function parseSseFrame(raw: string): SseFrame {
  let event = 'message';
  let id: string | null = null;
  const dataLines: string[] = [];

  for (const line of raw.split('\n')) {
    if (!line || line.startsWith(':')) continue;
    const separator = line.indexOf(':');
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '');
    if (field === 'event') event = value;
    else if (field === 'data') dataLines.push(value);
    else if (field === 'id') id = value;
  }

  return { event, data: dataLines.join('\n'), id };
}

/**
 * C-002: subscribes to the live traffic stream with an authenticated fetch
 * reader, exponential backoff from 1s to 30s, and a reconnect notification so
 * the console can re-fetch the pending queue.
 */
export function subscribeToTrafficStream(handlers: TrafficStreamHandlers): () => void {
  let disposed = false;
  let controller: AbortController | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  let hasConnected = false;

  const connect = async () => {
    if (disposed) return;
    handlers.onStatus?.(hasConnected ? 'reconnecting' : 'connecting');

    controller = new AbortController();
    let response: Response;
    try {
      response = await fetch(`${API_BASE}/stream/traffic`, {
        headers: authHeaders({
          Accept: 'text/event-stream',
          'Cache-Control': 'no-cache',
        }),
        signal: controller.signal,
        cache: 'no-store',
      });
    } catch {
      if (disposed) return;
      handlers.onError?.('The live traffic stream could not be reached.');
      scheduleRetry();
      return;
    }

    if (!response.ok) {
      if (disposed) return;
      let message = `The live traffic stream was refused with HTTP ${response.status}.`;
      try {
        const text = await response.text();
        if (text) {
          const parsed = JSON.parse(text) as ErrorBody;
          message = messageFromBody(parsed, response.status);
        }
      } catch {
        // Keep the status-bearing message.
      }
      handlers.onError?.(message);
      scheduleRetry();
      return;
    }

    if (!response.body) {
      handlers.onError?.('The live traffic stream returned no readable body.');
      scheduleRetry();
      return;
    }

    const wasReconnect = hasConnected;
    hasConnected = true;
    attempt = 0;
    handlers.onStatus?.('connected');
    if (wasReconnect) handlers.onReconnected?.();

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (!disposed) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');

        let boundary = buffer.indexOf('\n\n');
        while (boundary !== -1) {
          const raw = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          dispatchFrame(parseSseFrame(raw));
          boundary = buffer.indexOf('\n\n');
        }
      }
    } catch {
      if (disposed) return;
    }

    if (disposed) return;
    handlers.onError?.('The live traffic stream closed. Reconnecting…');
    scheduleRetry();
  };

  const dispatchFrame = (frame: SseFrame) => {
    if (!frame.data) return;
    try {
      const parsed = JSON.parse(frame.data) as Record<string, unknown>;
      if (frame.event === 'traffic') {
        handlers.onEvent(parsed as unknown as InspectorEvent);
      } else if (frame.event === 'approval') {
        handlers.onApproval?.(
          parsed as unknown as { ticketId: string; status: string; expiresAt: string }
        );
      } else if (frame.event === 'system') {
        handlers.onSystem?.(
          parsed as unknown as {
            status: SystemStatusResponse['status'];
            pendingApprovals: number;
          }
        );
      }
    } catch {
      // A malformed data frame is ignored; the stream itself stays healthy.
    }
  };

  const scheduleRetry = () => {
    if (disposed) return;
    handlers.onStatus?.('reconnecting');
    const delay = Math.min(30_000, 1_000 * 2 ** attempt);
    attempt += 1;
    retryTimer = setTimeout(connect, delay);
  };

  connect();

  return () => {
    disposed = true;
    controller?.abort();
    if (retryTimer) clearTimeout(retryTimer);
    handlers.onStatus?.('disconnected');
  };
}

export const AegisApi = {
  /** C-009 */
  getSystemStatus(): Promise<SystemStatusResponse> {
    return request<SystemStatusResponse>('/system/status');
  },

  /** C-010 */
  getMetricsSummary(): Promise<MetricsSummaryResponse> {
    return request<MetricsSummaryResponse>('/metrics/summary');
  },

  /** C-020 */
  getMetricsTimeseries(): Promise<MetricsTimeseriesResponse> {
    return request<MetricsTimeseriesResponse>('/metrics/timeseries');
  },

  /** C-003 */
  getPendingApprovals(limit = 50): Promise<ApprovalsResponse> {
    return request<ApprovalsResponse>(`/approvals/pending${query({ limit })}`);
  },

  /** C-019 */
  getApprovalHistory(
    status: ApprovalHistoryStatus,
    limit = 50,
    offset = 0
  ): Promise<ApprovalHistoryResponse> {
    return request<ApprovalHistoryResponse>(`/approvals${query({ status, limit, offset })}`);
  },

  /** C-004 */
  approveTicket(ticketId: string): Promise<ApprovalDecisionResponse> {
    return request<ApprovalDecisionResponse>(
      `/approvals/${encodeURIComponent(ticketId)}/approve`,
      { method: 'POST' }
    );
  },

  /** C-014 */
  rejectTicket(ticketId: string, reason: string): Promise<ApprovalRejectionResponse> {
    return request<ApprovalRejectionResponse>(
      `/approvals/${encodeURIComponent(ticketId)}/reject`,
      { method: 'POST', body: JSON.stringify({ reason }) }
    );
  },

  /** C-005 */
  getPolicies(status?: 'active' | 'draft' | 'archived'): Promise<PoliciesResponse> {
    return request<PoliciesResponse>(`/policies${query({ status })}`);
  },

  /** C-006 */
  publishPolicy(req: CreatePolicyRequest): Promise<CreatePolicyResponse> {
    return request<CreatePolicyResponse>('/policies', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  /** C-017 */
  getActivePolicy(): Promise<PolicyRecord> {
    return request<PolicyRecord>('/policies/active');
  },

  /** C-018 */
  activatePolicy(req: ActivatePolicyRequest): Promise<PolicyRecord> {
    return request<PolicyRecord>('/policies/active', {
      method: 'PUT',
      body: JSON.stringify(req),
    });
  },

  /** C-015 */
  getLedgerIntegrity(): Promise<AuditIntegrityResponse> {
    return request<AuditIntegrityResponse>('/audit/integrity');
  },

  /** C-013 */
  getAuditRecords(params: {
    agentId?: string;
    toolName?: string;
    decision?: 'allow' | 'block' | 'require_approval';
    blockHash?: string;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<AuditRecordsResponse> {
    return request<AuditRecordsResponse>(`/audit/records${query(params)}`);
  },

  /** C-016 */
  getViolations(params: {
    agentId?: string;
    violationType?: ViolationType;
    severity?: ViolationSeverity;
    from?: string;
    to?: string;
    limit?: number;
  } = {}): Promise<SecurityViolation[]> {
    return request<{ violations: SecurityViolation[] }>(
      `/audit/violations${query(params)}`
    ).then((response) => response.violations);
  },

  /** C-011 */
  exportComplianceReport(
    req: ComplianceExportRequest
  ): Promise<ComplianceExportResponse | ComplianceExportAcceptedResponse> {
    return request<ComplianceExportResponse | ComplianceExportAcceptedResponse>(
      '/compliance/export',
      { method: 'POST', body: JSON.stringify(req) }
    );
  },

  /** C-012 */
  simulatePolicy(req: PolicySimulateRequest): Promise<PolicySimulateResponse> {
    return request<PolicySimulateResponse>('/policies/simulate', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  /** C-008 */
  triggerEmergencyKill(req: EmergencyKillRequest): Promise<EmergencyKillResponse> {
    return request<EmergencyKillResponse>('/emergency/kill', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  },

  subscribeToTrafficStream,
};
