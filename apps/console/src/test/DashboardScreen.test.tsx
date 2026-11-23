/**
 * Specification Anchors: FEAT-008, FEAT-010, C-009, C-010, C-016, C-020
 * Dashboard screen states against contract fixtures held in this test module.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DashboardScreen } from '../screens/DashboardScreen';
import { AegisApi } from '../services/api';
import {
  ApprovalTicket,
  MetricsSummaryResponse,
  MetricsTimeseriesResponse,
  SecurityViolation,
  SystemStatusResponse,
} from '../types/contracts';

const STATUS: SystemStatusResponse = {
  status: 'NORMAL',
  activeConnections: 42,
  connectedNodes: 3,
  totalRequests24h: 1800,
  blockedViolations24h: 12,
  pendingApprovals: 1,
};

const METRICS: MetricsSummaryResponse = {
  activeAgents: 17,
  toolCalls24h: 1800,
  blockedViolations24h: 12,
  pendingApprovals: 1,
  uptimeSeconds: 90000,
};

const SERIES: MetricsTimeseriesResponse = {
  interval: 'HOUR',
  buckets: Array.from({ length: 24 }, (_, index) => ({
    bucketStart: new Date(Date.now() - (23 - index) * 3600_000).toISOString(),
    toolCalls: 40 + index,
    blockedViolations: index % 5,
  })),
};

const VIOLATIONS: SecurityViolation[] = [
  {
    id: 'viol-1',
    agentId: 'spiffe://example.org/ns/agents/sa/triage-bot',
    violationType: 'prompt_injection',
    blockHash: 'a'.repeat(64),
    severity: 'critical',
    details: 'Instruction override attempt in retrieved document.',
    createdAt: new Date().toISOString(),
  },
];

const PENDING: ApprovalTicket[] = [
  {
    id: 'appr-1',
    agentId: 'spiffe://example.org/ns/agents/sa/settlement-worker',
    toolName: 'payments_transfer',
    argumentsPayload: '{"amount":2500}',
    triggerPolicyId: 'SEC-02',
    agentIntent: 'Settle an approved invoice.',
    status: 'pending',
    createdAt: new Date(Date.now() - 30000).toISOString(),
    expiresAt: new Date(Date.now() + 240000).toISOString(),
  },
];

describe('DashboardScreen', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(AegisApi, 'getSystemStatus').mockResolvedValue(STATUS);
    vi.spyOn(AegisApi, 'getMetricsSummary').mockResolvedValue(METRICS);
    vi.spyOn(AegisApi, 'getMetricsTimeseries').mockResolvedValue(SERIES);
    vi.spyOn(AegisApi, 'getViolations').mockResolvedValue(VIOLATIONS);
    vi.spyOn(AegisApi, 'getPendingApprovals').mockResolvedValue({ tickets: PENDING });
  });

  it('renders gateway posture, metrics, violations, and pending approvals', async () => {
    render(
      <DashboardScreen
        onNavigateTo={vi.fn()}
        onOpenKillSwitch={vi.fn()}
        threatLevel={null}
      />
    );

    expect(await screen.findByTestId('threat-level-badge')).toHaveTextContent('NORMAL');
    expect(await screen.findByTestId('metric-active-agents')).toHaveTextContent('17');
    expect(await screen.findByTestId('metric-tool-calls')).toHaveTextContent('1,800');
    expect(await screen.findByTestId('metric-blocked-violations')).toHaveTextContent('12');
    expect(await screen.findByTestId('metric-pending-approvals')).toHaveTextContent('1');

    expect(await screen.findByText('Recent Security Violations')).toBeInTheDocument();
    expect(screen.getByText('prompt injection')).toBeInTheDocument();
    expect(screen.getByText('triage-bot')).toBeInTheDocument();
    expect(screen.getByText('payments_transfer')).toBeInTheDocument();
  });

  it('opens the emergency kill-switch from the dashboard', async () => {
    const onOpenKillSwitch = vi.fn();
    render(
      <DashboardScreen onNavigateTo={vi.fn()} onOpenKillSwitch={onOpenKillSwitch} threatLevel={null} />
    );

    fireEvent.click(await screen.findByTestId('emergency-killswitch-trigger'));
    expect(onOpenKillSwitch).toHaveBeenCalledTimes(1);
  });

  it('navigates to the approvals queue from the pending metric', async () => {
    const onNavigateTo = vi.fn();
    render(
      <DashboardScreen onNavigateTo={onNavigateTo} onOpenKillSwitch={vi.fn()} threatLevel={null} />
    );

    fireEvent.click(await screen.findByTestId('metric-pending-approvals'));
    expect(onNavigateTo).toHaveBeenCalledWith('approvals');
  });

  it('renders locked-down posture from the gateway', async () => {
    vi.spyOn(AegisApi, 'getSystemStatus').mockResolvedValue({ ...STATUS, status: 'LOCKDOWN' });

    render(
      <DashboardScreen onNavigateTo={vi.fn()} onOpenKillSwitch={vi.fn()} threatLevel={null} />
    );

    expect(await screen.findByTestId('threat-level-badge')).toHaveTextContent('LOCKDOWN');
    expect(screen.getByText(/Emergency lockdown active/i)).toBeInTheDocument();
  });

  it('shows a true empty state when the violation feed has no records', async () => {
    vi.spyOn(AegisApi, 'getViolations').mockResolvedValue([]);
    vi.spyOn(AegisApi, 'getPendingApprovals').mockResolvedValue({ tickets: [] });

    render(
      <DashboardScreen onNavigateTo={vi.fn()} onOpenKillSwitch={vi.fn()} threatLevel={null} />
    );

    expect(await screen.findByText('No security violations')).toBeInTheDocument();
    expect(screen.getByText('No agent calls are waiting for a human decision.')).toBeInTheDocument();
  });

  it('shows the error state and retries after a gateway failure', async () => {
    vi.spyOn(AegisApi, 'getSystemStatus').mockRejectedValueOnce(new Error('Gateway timeout'));

    render(
      <DashboardScreen onNavigateTo={vi.fn()} onOpenKillSwitch={vi.fn()} threatLevel={null} />
    );

    expect(await screen.findByTestId('error-state')).toBeInTheDocument();
    expect(screen.getByText('Gateway timeout')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('retry-button'));

    await waitFor(() => {
      expect(screen.queryByTestId('error-state')).not.toBeInTheDocument();
    });
  });
});
