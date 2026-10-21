/**
 * Specification Anchors: FEAT-008, C-008, C-009
 * KillSwitchModal and App Integration Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { KillSwitchModal } from '../components/KillSwitchModal';
import { App } from '../App';

describe('KillSwitchModal Component', () => {
  const onClose = vi.fn();
  const onConfirm = vi.fn().mockResolvedValue({
    status: 'QUARANTINED',
    affectedSessions: 64,
    timestamp: new Date().toISOString(),
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders confirmation dialog and enforces explicit LOCKDOWN typing', async () => {
    render(
      <KillSwitchModal
        isOpen={true}
        onClose={onClose}
        onConfirm={onConfirm}
      />
    );

    expect(screen.getByText('Emergency Cluster Kill-Switch')).toBeInTheDocument();

    const tripBtn = screen.getByTestId('trip-killswitch-button');
    expect(tripBtn).toBeDisabled();

    // Type justification reason
    const reasonTextarea = screen.getByPlaceholderText(/Active prompt injection chain detected/i);
    fireEvent.change(reasonTextarea, {
      target: { value: 'Cluster security breach suspected in payment worker' },
    });

    // Still disabled without typing LOCKDOWN
    expect(tripBtn).toBeDisabled();

    // Type LOCKDOWN in confirmation field
    const confirmInput = screen.getByTestId('lockdown-confirm-input');
    fireEvent.change(confirmInput, { target: { value: 'LOCKDOWN' } });

    expect(tripBtn).not.toBeDisabled();

    // Submit
    fireEvent.click(tripBtn);

    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledWith({
        targetType: 'global',
        targetId: 'cluster-production-eu1',
        reason: 'Cluster security breach suspected in payment worker',
      });
      expect(onClose).toHaveBeenCalled();
    });
  });
});

describe('App Component Shell and Navigation', () => {
  it('renders app shell with navbar, sidebar, and switches screens', async () => {
    render(<App />);

    expect(screen.getByText('Aegis')).toBeInTheDocument();
    expect(screen.getByText('MCP')).toBeInTheDocument();
    expect(screen.getByText('Elena Rostova')).toBeInTheDocument();

    // Default screen is Dashboard
    expect(await screen.findByTestId('threat-banner')).toBeInTheDocument();

    // Navigate to Inspector
    const inspectorNav = screen.getByTestId('nav-item-inspector');
    fireEvent.click(inspectorNav);
    expect(await screen.findByPlaceholderText(/Filter tool, agent, or event ID/i)).toBeInTheDocument();

    // Navigate to Approvals
    const approvalsNav = screen.getByTestId('nav-item-approvals');
    fireEvent.click(approvalsNav);
    expect(await screen.findByText('Human-in-the-Loop Approvals')).toBeInTheDocument();

    // Navigate to Policies
    const policiesNav = screen.getByTestId('nav-item-policies');
    fireEvent.click(policiesNav);
    expect(await screen.findByText('Declarative Policy Manager')).toBeInTheDocument();

    // Navigate to Audit
    const auditNav = screen.getByTestId('nav-item-audit');
    fireEvent.click(auditNav);
    expect(await screen.findByTestId('audit-integrity-banner')).toBeInTheDocument();
  });
});
