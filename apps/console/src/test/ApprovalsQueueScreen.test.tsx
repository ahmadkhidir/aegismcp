/**
 * Specification Anchors: FEAT-006, FEAT-008, C-003, C-004
 * Approvals Queue Screen Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ApprovalsQueueScreen } from '../screens/ApprovalsQueueScreen';
import { AegisApi } from '../services/api';

describe('ApprovalsQueueScreen Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders pending approval tickets with risk scores and remaining TTL', async () => {
    render(<ApprovalsQueueScreen />);

    expect(await screen.findByText('Human-in-the-Loop Approvals')).toBeInTheDocument();
    expect(await screen.findByText('stripe_charge_create')).toBeInTheDocument();
    expect(screen.getByText('k8s_delete_namespace')).toBeInTheDocument();
    expect(screen.getByText('user_reset_credentials')).toBeInTheDocument();

    // Check risk score pills
    expect(screen.getByText('Risk: 88/100')).toBeInTheDocument();
    expect(screen.getByText('Risk: 92/100')).toBeInTheDocument();
  });

  it('approves a ticket and dispatches C-004 decision', async () => {
    const submitSpy = vi.spyOn(AegisApi, 'submitApprovalDecision');

    render(<ApprovalsQueueScreen />);

    const approveBtn = await screen.findByTestId('approve-button-appr-401');
    fireEvent.click(approveBtn);

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledWith(
        'appr-401',
        expect.objectContaining({
          decision: 'APPROVE',
        })
      );
    });

    // Verify card is removed from view
    await waitFor(() => {
      expect(screen.queryByTestId('approval-ticket-appr-401')).not.toBeInTheDocument();
    });
  });

  it('rejects a ticket via rejection modal and dispatches C-004 with reason', async () => {
    const submitSpy = vi.spyOn(AegisApi, 'submitApprovalDecision');

    render(<ApprovalsQueueScreen />);

    // Click reject on ticket appr-402
    const rejectBtn = await screen.findByTestId('reject-button-appr-402');
    fireEvent.click(rejectBtn);

    // Rejection modal appears
    expect(screen.getByText('Reject Approval Ticket')).toBeInTheDocument();

    // Fill rejection reason
    const reasonInput = screen.getByTestId('rejection-reason-input');
    fireEvent.change(reasonInput, {
      target: { value: 'Destructive deletion denied by platform safety policy' },
    });

    // Confirm rejection
    const confirmBtn = screen.getByTestId('confirm-reject-button');
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledWith(
        'appr-402',
        expect.objectContaining({
          decision: 'REJECT',
          reason: 'Destructive deletion denied by platform safety policy',
        })
      );
    });

    // Modal closes and card removed
    await waitFor(() => {
      expect(screen.queryByTestId('approval-ticket-appr-402')).not.toBeInTheDocument();
    });
  });

  it('switches tabs and displays empty state when queue has no items', async () => {
    vi.spyOn(AegisApi, 'getApprovals').mockResolvedValue({ tickets: [] });

    render(<ApprovalsQueueScreen />);

    const rejectedTab = await screen.findByTestId('tab-rejected');
    fireEvent.click(rejectedTab);

    await waitFor(() => {
      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    });
  });
});
