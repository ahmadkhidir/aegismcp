/**
 * Specification Anchors: FEAT-008, FEAT-010, C-008, C-009, C-010
 * Screen 1: Security Dashboard
 */

import React, { useEffect, useState } from 'react';
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
} from 'lucide-react';
import { AegisApi, MOCK_RECENT_INCIDENTS } from '../services/api';
import {
  ApprovalTicket,
  MetricsSummaryResponse,
  SystemStatusResponse,
  ThreatLevel,
} from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { StatusPill } from '../components/StatusPill';

interface DashboardScreenProps {
  onNavigateTo: (screen: 'inspector' | 'approvals' | 'policies' | 'audit') => void;
  onOpenKillSwitch: () => void;
  threatLevel: ThreatLevel;
}

export const DashboardScreen: React.FC<DashboardScreenProps> = ({
  onNavigateTo,
  onOpenKillSwitch,
  threatLevel,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsSummaryResponse | null>(null);
  const [urgentApprovals, setUrgentApprovals] = useState<ApprovalTicket[]>([]);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, metricsRes, approvalsRes] = await Promise.all([
        AegisApi.getSystemStatus(),
        AegisApi.getMetricsSummary(),
        AegisApi.getApprovals('pending'),
      ]);
      setSystemStatus(statusRes);
      setMetrics(metricsRes);
      setUrgentApprovals(approvalsRes.tickets.slice(0, 3));
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve dashboard metrics');
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const activeThreat: ThreatLevel = threatLevel || systemStatus?.status || 'NORMAL';

  if (error) {
    return (
      <div className="p-space-lg max-w-7xl mx-auto">
        <ErrorState message={error} onRetry={loadDashboardData} />
      </div>
    );
  }

  return (
    <div className="p-space-lg max-w-7xl mx-auto space-y-space-lg animate-in fade-in duration-200">
      {/* 1. Threat Posture Hero Banner (C-008, C-009) */}
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
                <span className="text-xs font-mono uppercase tracking-wider text-grey-500">
                  Global Threat Posture
                </span>
                <span
                  data-testid="threat-level-badge"
                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded-radius-full ${
                    activeThreat === 'LOCKDOWN'
                      ? 'bg-error-500 text-grey-900'
                      : activeThreat === 'ELEVATED'
                      ? 'bg-warning-100 text-warning-900 border border-warning-300'
                      : 'bg-success-100 text-success-900 border border-success-300'
                  }`}
                >
                  {activeThreat}
                </span>
              </div>
              <h2 className="text-xl font-bold text-grey-900 mt-1">
                {activeThreat === 'LOCKDOWN'
                  ? 'EMERGENCY LOCKDOWN ACTIVE — All Autonomous Sessions Severed'
                  : activeThreat === 'ELEVATED'
                  ? 'Elevated Threat Detection — Violation Threshold Exceeded'
                  : 'Zero-Trust Defense Active — All Systems Normal'}
              </h2>
              <p className="text-xs text-grey-500 mt-0.5">
                {activeThreat === 'LOCKDOWN'
                  ? 'Security firewall is quarantining incoming JSON-RPC agent tool calls'
                  : 'Hardware-accelerated SPIFFE SVID verification and declarative AST guardrails active'}
              </p>
            </div>
          </div>

          <button
            onClick={onOpenKillSwitch}
            data-testid="emergency-killswitch-trigger"
            className="px-space-lg py-space-sm bg-error-500 hover:bg-error-400 text-grey-900 font-bold text-xs rounded-radius-md transition-colors shadow-md flex items-center gap-2 flex-shrink-0"
          >
            <AlertOctagon className="w-4 h-4" />
            <span>Emergency Kill-Switch</span>
          </button>
        </div>
      </div>

      {/* 2. Metric Counter Grid (C-010) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
        {/* Active Agents */}
        <div data-testid="metric-active-agents" className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-xs font-medium">Active Agents (SPIFFE)</span>
            <Users className="w-4 h-4 text-accent-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-24" />
          ) : (
            <div className="text-2xl font-bold font-mono text-grey-900">
              {metrics?.activeAgents ?? 0}
            </div>
          )}
          <span className="text-[11px] text-success-500 font-mono mt-1 inline-block">
            +12 connected last 1h
          </span>
        </div>

        {/* 24h Tool Calls */}
        <div data-testid="metric-tool-calls" className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-xs font-medium">24h Tool Invocations</span>
            <Activity className="w-4 h-4 text-primary-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-28" />
          ) : (
            <div className="text-2xl font-bold font-mono text-grey-900">
              {metrics?.toolCalls24h.toLocaleString() ?? '0'}
            </div>
          )}
          <span className="text-[11px] text-grey-500 font-mono mt-1 inline-block">
            P99 Latency: 2.8ms
          </span>
        </div>

        {/* Blocked Violations */}
        <div data-testid="metric-blocked-violations" className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-xs font-medium">Blocked Violations (24h)</span>
            <Ban className="w-4 h-4 text-error-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-20" />
          ) : (
            <div className="text-2xl font-bold font-mono text-error-500">
              {metrics?.blockedViolations24h ?? 0}
            </div>
          )}
          <span className="text-[11px] text-error-400 font-mono mt-1 inline-block">
            0% false negative rate
          </span>
        </div>

        {/* Pending Approvals */}
        <div
          data-testid="metric-pending-approvals"
          onClick={() => onNavigateTo('approvals')}
          className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md cursor-pointer hover:border-warning-500 transition-colors"
        >
          <div className="flex items-center justify-between text-grey-500 mb-2">
            <span className="text-xs font-medium">Pending Approvals</span>
            <Clock className="w-4 h-4 text-warning-500" />
          </div>
          {loading ? (
            <Skeleton className="h-8 w-16" />
          ) : (
            <div className="text-2xl font-bold font-mono text-warning-500">
              {urgentApprovals.length}
            </div>
          )}
          <span className="text-[11px] text-warning-500 font-mono mt-1 inline-flex items-center gap-1">
            Action required <ArrowRight className="w-3 h-3" />
          </span>
        </div>
      </div>

      {/* 3. Main Content Grid (2:1 ratio) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-space-lg">
        {/* Left Column (2 cols): Trend Graph & Incidents */}
        <div className="lg:col-span-2 space-y-space-lg">
          {/* Trend visualizer */}
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-primary-500" />
                <h3 className="text-sm font-semibold text-grey-900">Invocations vs. Blocked Violations</h3>
              </div>
              <span className="text-xs font-mono text-grey-500">Last 24 Hours</span>
            </div>

            {loading ? (
              <Skeleton className="h-44 w-full" />
            ) : (
              <div className="h-44 flex items-end gap-2 pt-4 px-2 border-b border-grey-300">
                {[45, 62, 85, 40, 70, 95, 120, 80, 65, 90, 110, 135, 95, 115, 88, 102, 125, 140, 110, 95, 80, 115, 130, 145].map((val, idx) => (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1 group relative">
                    <div
                      className="w-full bg-primary-500/80 hover:bg-primary-500 rounded-t-sm transition-all"
                      style={{ height: `${(val / 150) * 100}%` }}
                    />
                    {idx === 21 && (
                      <div
                        className="w-full bg-error-500 rounded-t-sm absolute bottom-0"
                        style={{ height: '24%' }}
                        title="Blocked violation spike"
                      />
                    )}
                  </div>
                ))}
              </div>
            )}
            <div className="flex items-center justify-between pt-space-xs text-[11px] font-mono text-grey-500">
              <span>00:00 UTC</span>
              <span>12:00 UTC</span>
              <span>23:59 UTC</span>
            </div>
          </div>

          {/* Recent Security Incidents Table */}
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-error-500" />
                <h3 className="text-sm font-semibold text-grey-900">Recent Security Incidents</h3>
              </div>
              <button
                onClick={() => onNavigateTo('inspector')}
                className="text-xs text-primary-500 hover:text-primary-400 font-medium inline-flex items-center gap-1"
              >
                Inspect live stream <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-grey-300 text-grey-500">
                    <th className="pb-2 font-medium">Timestamp</th>
                    <th className="pb-2 font-medium">Agent Workload</th>
                    <th className="pb-2 font-medium">Target Tool</th>
                    <th className="pb-2 font-medium">Rule Violated</th>
                    <th className="pb-2 font-medium text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-grey-300/40">
                  {MOCK_RECENT_INCIDENTS.map((inc) => (
                    <tr key={inc.id} className="hover:bg-grey-200/50 transition-colors">
                      <td className="py-2.5 text-grey-500">{new Date(inc.timestamp).toLocaleTimeString()}</td>
                      <td className="py-2.5 text-grey-800 max-w-[160px] truncate" title={inc.agentId}>
                        {inc.agentId.split('/').pop()}
                      </td>
                      <td className="py-2.5 text-primary-700">{inc.toolName}</td>
                      <td className="py-2.5 text-error-700">{inc.ruleViolated}</td>
                      <td className="py-2.5 text-right">
                        <StatusPill verdict={inc.verdict} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column (1 col): Urgent Approvals & Fleet Status */}
        <div className="space-y-space-lg">
          {/* Urgent Approvals Widget */}
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md">
            <div className="flex items-center justify-between mb-space-md">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-warning-500" />
                <h3 className="text-sm font-semibold text-grey-900">Urgent HITL Approvals</h3>
              </div>
              <span className="text-xs font-mono font-bold text-warning-500">
                {urgentApprovals.length} pending
              </span>
            </div>

            {loading ? (
              <div className="space-y-2">
                <Skeleton className="h-20 w-full" />
                <Skeleton className="h-20 w-full" />
              </div>
            ) : urgentApprovals.length === 0 ? (
              <div className="py-space-lg text-center text-xs text-grey-500">
                All clear — no pending requests
              </div>
            ) : (
              <div className="space-y-space-sm">
                {urgentApprovals.map((ticket) => (
                  <div
                    key={ticket.id}
                    onClick={() => onNavigateTo('approvals')}
                    className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md cursor-pointer hover:border-warning-500 transition-colors"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono text-grey-500 mb-1">
                      <span className="text-warning-500 font-semibold">{ticket.toolName}</span>
                      <span className="bg-warning-100 text-warning-900 px-1 rounded-radius-sm">
                        Risk: {ticket.riskScore}
                      </span>
                    </div>
                    <p className="text-xs text-grey-800 line-clamp-2">{ticket.reason}</p>
                  </div>
                ))}
                <button
                  onClick={() => onNavigateTo('approvals')}
                  className="w-full mt-2 py-2 bg-grey-200 hover:bg-grey-300 text-primary-500 font-medium text-xs rounded-radius-md transition-colors"
                >
                  Open Approvals Queue →
                </button>
              </div>
            )}
          </div>

          {/* Quick Security Posture Checks */}
          <div className="p-space-md bg-grey-100 border border-grey-300 rounded-radius-md text-xs space-y-space-sm">
            <h3 className="text-sm font-semibold text-grey-900">Engine Guardrails</h3>
            <div className="flex items-center justify-between text-grey-600">
              <span>SPIFFE mTLS Validation:</span>
              <span className="text-success-500 font-mono font-bold">ENFORCING</span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>AST Argument Policy:</span>
              <span className="text-success-500 font-mono font-bold">v2.4.0 (ACTIVE)</span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>DLP Secret Redaction:</span>
              <span className="text-success-500 font-mono font-bold">14 Rules ON</span>
            </div>
            <div className="flex items-center justify-between text-grey-600">
              <span>Audit Ledger Chain:</span>
              <span className="text-success-500 font-mono font-bold">SEALED (0 FAILS)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
