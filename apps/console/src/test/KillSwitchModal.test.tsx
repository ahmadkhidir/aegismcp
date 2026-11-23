/**
 * Specification Anchors: FEAT-008, C-008, C-009
 * Kill-switch confirmation and the authenticated application shell.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { KillSwitchModal } from '../components/KillSwitchModal';
import { App } from '../App';
import { AegisApi, ApiError } from '../services/api';

function base64Url(value: string): string {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function seedSession() {
  const token = `${base64Url(JSON.stringify({ alg: 'RS256' }))}.${base64Url(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })
  )}.test-signature`;

  sessionStorage.setItem(
    'aegis_auth_session',
    JSON.stringify({
      user: {
        sub: 'user-42',
        name: 'Ada Lovelace',
        email: 'ada@example.com',
        roles: ['admin'],
        idp: 'https://idp.test/realms/aegis',
        sessionExpiresAt: Date.now() + 900000,
      },
      tokens: {
        idToken: token,
        accessToken: 'test-access-token',
        expiresIn: 3600,
        tokenType: 'Bearer',
        scope: 'openid profile email roles',
      },
    })
  );
}

describe('KillSwitchModal', () => {
  const onClose = vi.fn();
  const onConfirm = vi.fn().mockResolvedValue({
    status: 'LOCKDOWN',
    affectedSessions: 64,
    timestamp: new Date().toISOString(),
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('requires explicit LOCKDOWN confirmation and sends no target for a global stop', async () => {
    render(<KillSwitchModal isOpen={true} onClose={onClose} onConfirm={onConfirm} />);

    expect(screen.getByText('Emergency Cluster Kill-Switch')).toBeInTheDocument();
    const tripButton = screen.getByTestId('trip-killswitch-button');
    expect(tripButton).toBeDisabled();

    fireEvent.change(screen.getByPlaceholderText(/Active prompt injection chain detected/i), {
      target: { value: 'Containment after a confirmed prompt injection.' },
    });
    expect(tripButton).toBeDisabled();

    fireEvent.change(screen.getByTestId('lockdown-confirm-input'), {
      target: { value: 'LOCKDOWN' },
    });
    expect(tripButton).not.toBeDisabled();

    fireEvent.click(tripButton);

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith({
        targetType: 'global',
        reason: 'Containment after a confirmed prompt injection.',
      });
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('carries the identifier for a scoped target', async () => {
    render(<KillSwitchModal isOpen={true} onClose={onClose} onConfirm={onConfirm} />);

    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'agent' } });
    fireEvent.change(screen.getByPlaceholderText('spiffe://...'), {
      target: { value: 'spiffe://example.org/ns/agents/sa/triage-bot' },
    });
    fireEvent.change(screen.getByPlaceholderText(/Active prompt injection chain detected/i), {
      target: { value: 'Quarantine a compromised workload identity.' },
    });
    fireEvent.change(screen.getByTestId('lockdown-confirm-input'), {
      target: { value: 'LOCKDOWN' },
    });
    fireEvent.click(screen.getByTestId('trip-killswitch-button'));

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith({
        targetType: 'agent',
        targetId: 'spiffe://example.org/ns/agents/sa/triage-bot',
        reason: 'Quarantine a compromised workload identity.',
      });
    });
  });
});

describe('App shell', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
    window.location.hash = '';
    seedSession();

    vi.spyOn(AegisApi, 'getSystemStatus').mockResolvedValue({
      status: 'NORMAL',
      activeConnections: 12,
      connectedNodes: 2,
      totalRequests24h: 400,
      blockedViolations24h: 3,
      pendingApprovals: 0,
    });
    vi.spyOn(AegisApi, 'getMetricsSummary').mockResolvedValue({
      activeAgents: 8,
      toolCalls24h: 400,
      blockedViolations24h: 3,
      pendingApprovals: 0,
      uptimeSeconds: 3600,
    });
    vi.spyOn(AegisApi, 'getMetricsTimeseries').mockResolvedValue({ interval: 'HOUR', buckets: [] });
    vi.spyOn(AegisApi, 'getViolations').mockResolvedValue([]);
    vi.spyOn(AegisApi, 'getPendingApprovals').mockResolvedValue({ tickets: [] });
    vi.spyOn(AegisApi, 'getApprovalHistory').mockResolvedValue({ tickets: [], total: 0 });
    vi.spyOn(AegisApi, 'getPolicies').mockResolvedValue({ policies: [] });
    vi.spyOn(AegisApi, 'getActivePolicy').mockRejectedValue(
      new ApiError(404, 'No policy version is active yet.')
    );
    vi.spyOn(AegisApi, 'getAuditRecords').mockResolvedValue({ records: [], total: 0 });
    vi.spyOn(AegisApi, 'getLedgerIntegrity').mockResolvedValue({
      valid: true,
      totalVerifiedBlocks: 0,
      lastVerifiedAt: new Date().toISOString(),
    });
    vi.spyOn(AegisApi, 'subscribeToTrafficStream').mockImplementation(() => () => {});
  });

  it('renders the authenticated shell and switches screens', async () => {
    render(<App />);

    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
    expect(await screen.findByTestId('threat-banner')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('nav-item-inspector'));
    expect(await screen.findByPlaceholderText(/Filter tool, agent, or event ID/i)).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('nav-item-approvals'));
    expect(await screen.findByText('Human-in-the-Loop Approvals')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('nav-item-policies'));
    expect(await screen.findByText('Declarative Policy Manager')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('nav-item-audit'));
    expect(await screen.findByTestId('audit-integrity-banner')).toBeInTheDocument();
  });
});
