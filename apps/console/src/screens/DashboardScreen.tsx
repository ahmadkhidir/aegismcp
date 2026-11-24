/**
 * Specification Anchors: FEAT-008, FEAT-010, C-008, C-009, C-010, C-016, C-020
 * Screen 1: Security Dashboard. Every number and row is sourced from the
 * gateway; loading, empty, and error states are explicit.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  Users,
  Activity,
  Ban,
  Clock,
  ArrowRight,
  TrendingUp,
  Server,
} from 'lucide-react';
import { AegisApi } from '../services/api';
import {
  ApprovalTicket,
  MetricsSummaryResponse,
  MetricsTimeseriesResponse,
  SecurityViolation,
  SystemStatusResponse,
  ThreatLevel,
  ViolationSeverity,
} from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';

interface DashboardScreenProps {
  onNavigateTo: (screen: 'inspector' | 'approvals' | 'policies' | 'audit') => void;
  onOpenKillSwitch: () => void;
  threatLevel: ThreatLevel | null;
  /** C-003 admits admin and operator; other roles see the widget restricted. */
  canReadApprovals?: boolean;
  /** C-008 and C-021 admit admin and operator. */
  canOperateEmergency?: boolean;
}

const SEVERITY_CLASS: Record<ViolationSeverity, string> = {
  critical: 'bg-error-500 text-grey-900',
  high: 'bg-error-100 text-error-900 border border-error-300',
  medium: 'bg-warning-100 text-warning-900 border border-warning-300',
  low: 'bg-grey-200 text-grey-700 border border-grey-300',
};

function formatDuration(totalSeconds: number): string {
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({
  onNavigateTo,
  onOpenKillSwitch,
  threatLevel,
  canReadApprovals = true,
  canOperateEmergency = true,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsSummaryResponse | null>(null);
  const [timeseries, setTimeseries] = useState<MetricsTimeseriesResponse | null>(null);
  const [timeseriesUnavailable, setTimeseriesUnavailable] = useState(false);
  const [violations, setViolations] = useState<SecurityViolation[]>([]);
  const [violationsUnavailable, setViolationsUnavailable] = useState(false);
  const [urgentApprovals, setUrgentApprovals] = useState<ApprovalTicket[]>([]);

  const loadDashboardData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // C-003 is scoped to admin and operator. A role without it still reads
      // the fleet from C-009, C-010, C-016, and C-020 instead of failing the
      // whole dashboard on a refusal.
      const approvalsRequest = canReadApprovals
        ? AegisApi.getPendingApprovals(3)
        : Promise.resolve({ tickets: [] as ApprovalTicket[] });

      const [statusRes, metricsRes, approvalsRes] = await Promise.all([
        AegisApi.getSystemStatus(),
        AegisApi.getMetricsSummary(),
        approvalsRequest,
      ]);

      // The chart and the incident feed are secondary surfaces: a missing or
      // unavailable feed must not replace the whole dashboard with an error.
      const [seriesRes, violationsRes] = await Promise.allSettled([
        AegisApi.getMetricsTimeseries(),
        AegisApi.getViolations({ limit: 10 }),
      ]);

      setSystemStatus(statusRes);
      setMetrics(metricsRes);
      setUrgentApprovals(approvalsRes.tickets);

      if (seriesRes.status === 'fulfilled') {
        setTimeseries(seriesRes.value);
        setTimeseriesUnavailable(false);
      } else {
        setTimeseries(null);
        setTimeseriesUnavailable(true);
      }

      if (violationsRes.status === 'fulfilled') {
        setViolations(violationsRes.value);
        setViolationsUnavailable(false);
      } else {
        setViolations([]);
        setViolationsUnavailable(true);
      }

      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve dashboard metrics');
    }
  }, [canReadApprovals]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  const activeThreat: ThreatLevel | null = threatLevel ?? systemStatus?.status ?? null;
  const buckets = timeseries?.buckets ?? [];
  const maxCalls = Math.max(1, ...buckets.map((bucket) => bucket.toolCalls));
  const blockedPercent =
    metrics && metrics.toolCalls24h > 0
      ? ((metrics.blockedViolations24h / metrics.toolCalls24h) * 100).toFixed(1)
      : '0.0';

  if (error) {
    return (
      <div className="p-space-lg max-w-7xl mx-auto">
        <ErrorState message={error} onRetry={loadDashboardData} />
      </div>
    );
  }

  return (
    <div className="p-space-lg max-w-7xl mx-auto space-y-space-lg animate-in fade-in duration-200">
      <div
        data-testid="threat-banner"
        className={`p-space-lg rounded-radius-lg border transition-all ${
          activeThreat === 'LOCKDOWN'
            ? 'bg-error-100 border-error-500 shadow-xl'
            : activeThreat === 'ELEVATED'
            ? 'bg-warning-100/40 border-warning-300'
            : 'bg-grey-100 border-grey-300'
        }`}
      >
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md">
          <div className="flex items-center gap-space-md">
            <div
              className={`p-3 rounded-radius-md ${
                activeThreat === 'LOCKDOWN'
                  ? 'bg-error-500 text-grey-900 animate-pulse'
                  : activeThreat === 'ELEVATED'
                  ? 'bg-warning-500 text-grey-50'
                  : 'bg-success-500 text-grey-50'
              }`}
            >
              {activeThreat === 'LOCKDOWN' ? (
                <AlertOctagon className="w-8 h-8" />
              ) : activeThreat === 'ELEVATED' ? (
                <ShieldAlert className="w-8 h-8" />
              ) : (
                <ShieldCheck className="w-8 h-8" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-caption font-mono uppercase tracking-wider text-grey-500">
                  Global Threat Posture
                </span>
                <span
                  data-testid="threat-level-badge"
                  className={`text-caption font-mono font-bold px-2 py-0.5 rounded-radius-full ${
                    activeThreat === 'LOCKDOWN'
                      ? 'bg-error-500 text-grey-900'
                      : activeThreat === 'ELEVATED'
                      ? 'bg-warning-100 text-warning-900 border border-warning-300'
                      : 'bg-success-100 text-success-900 border border-success-300'
                  }`}
                >
                  {activeThreat ?? 'CHECKING'}
                </span>
              </div>
              <h2 className="text-h2 font-bold text-grey-900 mt-1">
                {activeThreat === 'LOCKDOWN'
                  ? 'Emergency lockdown active — autonomous sessions severed'
                  : activeThreat === 'ELEVATED'
                  ? 'Elevated threat detection — violation threshold exceeded'
                  : activeThreat === 'NORMAL'
                  ? 'Zero-trust defense active — all systems normal'
                  : 'Reading fleet posture from the gateway'}
              </h2>
              <p className="text-caption text-grey-500 mt-0.5">
                {activeThreat === 'LOCKDOWN'
                  ? 'The security firewall is quarantining incoming agent tool calls'
                  : 'SPIFFE identity verification and declarative AST guardrails are enforced on every call'}
              </p>
            </div>
          </div>

          {canOperateEmergency && (
            <button
              onClick={onOpenKillSwitch}
              data-testid="emergency-killswitch-trigger"
              className="px-space-lg py-space-sm bg-error-500 hover:bg-error-700 text-grey-900 font-bold text-caption rounded-radius-md transition-colors shadow-md flex items-center gap-2 flex-shrink-0"
            >
              <AlertOctagon className="w-4 h-4" />
              <span>Emergency Kill-Switch</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
        <div
          data-testid="metric-active-agents"
          className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md"
        >
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-caption font-medium">Active Agents (SPIFFE)</span>
            <Users className="w-4 h-4 text-accent-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-24" />
          ) : (
            <div className="text-h1 font-bold font-mono text-grey-900">
              {metrics?.activeAgents ?? 0}
            </div>
          )}
          <span className="text-caption text-grey-500 font-mono mt-1 inline-block">
            {systemStatus ? `${systemStatus.activeConnections} open sessions` : 'Awaiting fleet status'}
          </span>
        </div>

        <div
          data-testid="metric-tool-calls"
          className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md"
        >
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-caption font-medium">24h Tool Invocations</span>
            <Activity className="w-4 h-4 text-primary-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-28" />
          ) : (
            <div className="text-h1 font-bold font-mono text-grey-900">
              {(metrics?.toolCalls24h ?? 0).toLocaleString()}
            </div>
          )}
          <span className="text-caption text-grey-500 font-mono mt-1 inline-block">
            {metrics ? `Gateway uptime ${formatDuration(metrics.uptimeSeconds)}` : 'Awaiting metrics'}
          </span>
        </div>

        <div
          data-testid="metric-blocked-violations"
          className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md"
        >
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-caption font-medium">Blocked Violations (24h)</span>
            <Ban className="w-4 h-4 text-error-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-20" />
          ) : (
            <div className="text-h1 font-bold font-mono text-error-500">
              {metrics?.blockedViolations24h ?? 0}
            </div>
          )}
          <span className="text-caption text-grey-500 font-mono mt-1 inline-block">
            {blockedPercent}% of intercepted calls
          </span>
        </div>

        <div
          data-testid="metric-pending-approvals"
          onClick={canReadApprovals ? () => onNavigateTo('approvals') : undefined}
          className={`p-space-md bg-grey-100 border border-grey-300 rounded-radius-md ${
            canReadApprovals ? 'cursor-pointer hover:border-warning-500 transition-colors' : ''
          }`}
        >
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-caption font-medium">Pending Approvals</span>
            <Clock className="w-4 h-4 text-warning-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <div className="text-h1 font-bold font-mono text-warning-500">
              {canReadApprovals ? urgentApprovals.length : '-'}
            </div>
          )}
          <span className="text-caption text-warning-500 font-mono mt-1 inline-flex items-center gap-1">
            {canReadApprovals ? (
              <>
                Action required <ArrowRight className="w-3 h-3" />
              </>
            ) : (
              'Operator access required'
            )}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-space-lg">
        <div className="lg:col-span-2 space-y-space-lg">
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-primary-500" />
                <h3 className="text-body-small font-semibold text-grey-900">Invocations vs. Blocked Violations</h3>
              </div>
              <span className="text-caption font-mono text-grey-500">Last 24 Hours</span>
            </div>

            {loading ? (
              <Skeleton className="h-44 w-full" />
            ) : buckets.length === 0 ? (
              <div className="h-44 flex items-center justify-center text-caption text-grey-500">
                {timeseriesUnavailable
                  ? 'Telemetry feed unavailable. The gateway did not return the 24-hour series.'
                  : 'No telemetry for the last 24 hours.'}
              </div>
            ) : (
              <div className="h-44 flex items-end gap-1 pt-4 px-2 border-b border-grey-300">
                {buckets.map((bucket) => (
                  <div
                    key={bucket.bucketStart}
                    className="flex-1 flex flex-col justify-end h-full group relative"
                    title={`${new Date(bucket.bucketStart).toLocaleString()} — ${bucket.toolCalls} calls, ${bucket.blockedViolations} blocked`}
                  >
                    <div
                      className="w-full bg-primary-500/80 hover:bg-primary-500 rounded-t-sm transition-all"
                      style={{ height: `${(bucket.toolCalls / maxCalls) * 100}%` }}
                    />
                    {bucket.blockedViolations > 0 && (
                      <div
                        className="w-full bg-error-500 rounded-t-sm absolute bottom-0"
                        style={{ height: `${(bucket.blockedViolations / maxCalls) * 100}%` }}
                        aria-hidden="true"
                      />
                    )}
                  </div>
                ))}
              </div>
            )}
            <div className="flex items-center justify-between pt-space-xs text-caption font-mono text-grey-500">
              <span>{buckets[0] ? new Date(buckets[0].bucketStart).toLocaleTimeString() : '—'}</span>
              <span>{buckets.length > 0 ? 'Hourly buckets' : '—'}</span>
              <span>
                {buckets.length > 0
                  ? new Date(buckets[buckets.length - 1].bucketStart).toLocaleTimeString()
                  : '—'}
              </span>
            </div>
          </div>

          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-error-500" />
                <h3 className="text-body-small font-semibold text-grey-900">Recent Security Violations</h3>
              </div>
              <button
                onClick={() => onNavigateTo('inspector')}
                className="text-caption text-primary-500 hover:text-primary-400 font-medium inline-flex items-center gap-1"
              >
                Inspect live stream <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {loading ? (
              <div className="space-y-2">
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
              </div>
            ) : violationsUnavailable ? (
              <div className="py-8 text-center text-caption text-grey-500">
                Incident feed unavailable. The gateway did not return the security violation feed.
              </div>
            ) : violations.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No security violations"
                description="No blocked calls, validation rejections, anomalies, or kill-switch actions have been recorded."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-caption font-mono">
                  <thead>
                    <tr className="border-b border-grey-300 text-grey-500">
                      <th className="pb-2 font-medium">Time</th>
                      <th className="pb-2 font-medium">Agent Workload</th>
                      <th className="pb-2 font-medium">Violation</th>
                      <th className="pb-2 font-medium">Severity</th>
                      <th className="pb-2 font-medium text-right">Sealed Block</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-grey-300/40">
                    {violations.map((violation) => (
                      <tr key={violation.id} className="hover:bg-grey-200/50 transition-colors">
                        <td className="py-2.5 text-grey-500 whitespace-nowrap">
                          {new Date(violation.createdAt).toLocaleTimeString()}
                        </td>
                        <td
                          className="py-2.5 text-grey-800 max-w-[160px] truncate"
                          title={violation.agentId}
                        >
                          {violation.agentId.split('/').pop()}
                        </td>
                        <td className="py-2.5 text-error-700">
                          <span className="block">{violation.violationType.replace(/_/g, ' ')}</span>
                          <span className="block text-caption text-grey-500 font-sans">
                            {violation.details}
                          </span>
                        </td>
                        <td className="py-2.5">
                          <span
                            className={`inline-flex px-1.5 py-0.5 rounded-radius-sm text-caption font-bold uppercase ${SEVERITY_CLASS[violation.severity]}`}
                          >
                            {violation.severity}
                          </span>
                        </td>
                        <td
                          className="py-2.5 text-right text-grey-500 truncate max-w-[120px]"
                          title={violation.blockHash}
                        >
                          {violation.blockHash.slice(0, 10)}…
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-space-lg">
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-warning-500" />
                <h3 className="text-body-small font-semibold text-grey-900">Urgent HITL Approvals</h3>
              </div>
              <span className="text-caption font-mono font-bold text-warning-500">
                {urgentApprovals.length} pending
              </span>
            </div>

            {loading ? (
              <div className="space-y-2">
                <Skeleton className="h-20 w-full" />
                <Skeleton className="h-20 w-full" />
              </div>
            ) : !canReadApprovals ? (
              <div
                data-testid="approvals-restricted"
                className="py-space-lg text-center text-caption text-grey-500"
              >
                The pending approval queue is visible to operators and administrators.
              </div>
            ) : urgentApprovals.length === 0 ? (
              <div className="py-space-lg text-center text-caption text-grey-500">
                No agent calls are waiting for a human decision.
              </div>
            ) : (
              <div className="space-y-space-sm">
                {urgentApprovals.map((ticket) => (
                  <div
                    key={ticket.id}
                    onClick={() => onNavigateTo('approvals')}
                    className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md cursor-pointer hover:border-warning-500 transition-colors"
                  >
                    <div className="flex items-center justify-between text-caption font-mono text-grey-500 mb-1">
                      <span className="text-warning-500 font-semibold">{ticket.toolName}</span>
                      <span className="text-grey-500 truncate max-w-[10rem]">
                        {ticket.triggerPolicyId}
                      </span>
                    </div>
                    <p className="text-caption text-grey-800 line-clamp-2">
                      {ticket.agentIntent || 'No intent supplied by the requesting agent.'}
                    </p>
                  </div>
                ))}
                <button
                  onClick={() => onNavigateTo('approvals')}
                  className="w-full mt-2 py-2 bg-grey-200 hover:bg-grey-300 text-primary-500 font-medium text-caption rounded-radius-md transition-colors"
                >
                  Open Approvals Queue →
                </button>
              </div>
            )}
          </div>

          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md text-caption space-y-space-sm">
            <h3 className="text-body-small font-semibold text-grey-900 flex items-center gap-2">
              <Server className="w-4 h-4 text-primary-500" />
              Fleet Status
            </h3>
            <div className="flex items-center justify-between text-grey-600">
              <span>Threat level:</span>
              <span className="text-grey-900 font-mono font-bold">{activeThreat ?? '—'}</span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>Open agent sessions:</span>
              <span className="text-grey-900 font-mono font-bold">
                {systemStatus?.activeConnections ?? '—'}
              </span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>Reporting gateway nodes:</span>
              <span className="text-grey-900 font-mono font-bold">
                {systemStatus?.connectedNodes ?? '—'}
              </span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>Requests (24h):</span>
              <span className="text-grey-900 font-mono font-bold">
                {systemStatus ? systemStatus.totalRequests24h.toLocaleString() : '—'}
              </span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>Blocked (24h):</span>
              <span className="text-grey-900 font-mono font-bold">
                {systemStatus ? systemStatus.blockedViolations24h.toLocaleString() : '—'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
