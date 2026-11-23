/**
 * Specification Anchors: FEAT-006, FEAT-008, C-003, C-004, C-014, C-019
 * Approvals queue behaviour with contract fixtures held in this test module.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { ApprovalsQueueScreen } from '../screens/ApprovalsQueueScreen';
import { AegisApi } from '../services/api';
import { ApprovalHistoryTicket, ApprovalTicket } from '../types/contracts';

const PENDING: ApprovalTicket[] = [
  {
    id: 'appr-401',
    agentId: 'spiffe://example.org/ns/payments/sa/settlement-worker',
    toolName: 'payments_transfer',
    argumentsPayload: '{"amountCents":2500000,"customerToken":"[REDACTED]"}',
    triggerPolicyId: 'SEC-02',
    agentIntent: 'Settle the approved quarterly invoice.',
    status: 'pending',
    createdAt: new Date(Date.now() - 45000).toISOString(),
    expiresAt: new Date(Date.now() + 255000).toISOString(),
  },
  {
    id: 'appr-402',
    agentId: 'spiffe://example.org/ns/infra/sa/cloud-optimizer',
    toolName: 'k8s_delete_namespace',
    argumentsPayload: '{"namespace":"staging-legacy-eu"}',
    triggerPolicyId: 'SEC-07',
    agentIntent: null,
    status: 'pending',
    createdAt: new Date(Date.now() - 120000).toISOString(),
    expiresAt: new Date(Date.now() + 180000).toISOString(),
  },
];

const APPROVED_HISTORY: ApprovalHistoryTicket[] = [
  {
    id: 'appr-300',
    agentId: 'spiffe://example.org/ns/agents/sa/triage-bot',
    toolName: 'user_reset_credentials',
    argumentsPayload: '{"userId":"usr_883921"}',
    triggerPolicyId: 'SEC-09',
    status: 'approved',
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    expiresAt: new Date(Date.now() - 3000000).toISOString(),
    reviewedBy: 'operator@example.com',
    rejectionReason: null,
    processedAt: new Date(Date.now() - 3300000).toISOString(),
  },
];

describe('ApprovalsQueueScreen', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(AegisApi, 'getPendingApprovals').mockResolvedValue({ tickets: PENDING });
    vi.spyOn(AegisApi, 'getApprovalHistory').mockResolvedValue({
      tickets: APPROVED_HISTORY,
      total: APPROVED_HISTORY.length,
    });
    vi.spyOn(AegisApi, 'approveTicket').mockResolvedValue({
      ticketId: 'appr-401',
      status: 'approved',
      reviewedBy: 'operator@example.com',
      processedAt: new Date().toISOString(),
    });
    vi.spyOn(AegisApi, 'rejectTicket').mockResolvedValue({
      ticketId: 'appr-402',
      status: 'rejected',
      reviewedBy: 'operator@example.com',
      rejectionReason: 'Denied during change freeze.',
      processedAt: new Date().toISOString(),
    });
  });

  it('renders pending tickets with the triggering policy and agent intent', async () => {
    render(<ApprovalsQueueScreen />);

    expect(await screen.findByText('Human-in-the-Loop Approvals')).toBeInTheDocument();
    expect(await screen.findByText('payments_transfer')).toBeInTheDocument();
    expect(screen.getByText('k8s_delete_namespace')).toBeInTheDocument();
    expect(screen.getByText('Trigger: SEC-02')).toBeInTheDocument();
    expect(screen.getByText('Settle the approved quarterly invoice.')).toBeInTheDocument();
    expect(screen.getAllByText(/left$/).length).toBeGreaterThan(0);
  });

  it('approves a ticket through C-004 without sending a reviewer identity', async () => {
    const approve = vi.mocked(AegisApi.approveTicket);
    vi.mocked(AegisApi.getPendingApprovals)
      .mockResolvedValueOnce({ tickets: PENDING })
      .mockResolvedValue({ tickets: [] });

    render(<ApprovalsQueueScreen />);

    fireEvent.click(await screen.findByTestId('approve-button-appr-401'));

    await waitFor(() => {
      expect(approve).toHaveBeenCalledWith('appr-401');
    });
    await waitFor(() => {
      expect(screen.queryByTestId('approval-ticket-appr-401')).not.toBeInTheDocument();
    });
  });

  it('rejects a ticket with a mandatory reason through C-014', async () => {
    const reject = vi.mocked(AegisApi.rejectTicket);
    vi.mocked(AegisApi.getPendingApprovals)
      .mockResolvedValueOnce({ tickets: PENDING })
      .mockResolvedValue({ tickets: [] });

    render(<ApprovalsQueueScreen />);

    fireEvent.click(await screen.findByTestId('reject-button-appr-402'));
    expect(screen.getByText('Reject Approval Ticket')).toBeInTheDocument();

    fireEvent.change(screen.getByTestId('rejection-reason-input'), {
      target: { value: 'Denied during change freeze.' },
    });
    fireEvent.click(screen.getByTestId('confirm-reject-button'));

    await waitFor(() => {
      expect(reject).toHaveBeenCalledWith('appr-402', 'Denied during change freeze.');
    });
    await waitFor(() => {
      expect(screen.queryByText('Reject Approval Ticket')).not.toBeInTheDocument();
    });
  });

  it('loads approved history and shows the recorded reviewer', async () => {
    const history = vi.mocked(AegisApi.getApprovalHistory);
    render(<ApprovalsQueueScreen />);

    fireEvent.click(await screen.findByTestId('tab-approved'));

    await waitFor(() => {
      expect(history).toHaveBeenCalledWith('approved', 100, 0);
    });
    expect(await screen.findByText('operator@example.com')).toBeInTheDocument();
    expect(screen.queryByTestId('approve-button-appr-300')).not.toBeInTheDocument();
  });

  it('shows an empty state for a tab with no tickets', async () => {
    vi.mocked(AegisApi.getPendingApprovals).mockResolvedValue({ tickets: [] });
    render(<ApprovalsQueueScreen />);

    expect(await screen.findByText('No agent actions are waiting for approval')).toBeInTheDocument();
  });

  it('renders skeleton cards while the pending queue is loading', async () => {
    vi.mocked(AegisApi.getPendingApprovals).mockReturnValue(
      new Promise<{ tickets: ApprovalTicket[] }>(() => {})
    );
    render(<ApprovalsQueueScreen />);

    expect(await screen.findAllByRole('status')).not.toHaveLength(0);
  });

  it('opens resolved history for a role the pending queue refuses', async () => {
    const history = vi.mocked(AegisApi.getApprovalHistory);
    const pending = vi.mocked(AegisApi.getPendingApprovals);

    render(<ApprovalsQueueScreen canReviewPending={false} />);

    expect(await screen.findByText('operator@example.com')).toBeInTheDocument();
    expect(history).toHaveBeenCalledWith('approved', 100, 0);
    expect(pending).not.toHaveBeenCalled();
    expect(screen.queryByTestId('tab-pending')).not.toBeInTheDocument();
  });

  it('removes a ticket whose TTL expires while it is on screen', async () => {
    vi.mocked(AegisApi.getPendingApprovals).mockResolvedValue({
      tickets: [
        {
          ...PENDING[0],
          id: 'appr-expired',
          expiresAt: new Date(Date.now() - 1000).toISOString(),
        },
      ],
    });

    render(<ApprovalsQueueScreen />);

    expect(await screen.findByTestId('expired-tickets-notice')).toHaveTextContent(
      '1 request expired before a decision'
    );
    expect(screen.queryByTestId('approval-ticket-appr-expired')).not.toBeInTheDocument();
    expect(screen.queryByText('No agent actions are waiting for approval')).not.toBeInTheDocument();
  });

  it('names the active tab in an empty resolved history', async () => {
    vi.mocked(AegisApi.getApprovalHistory).mockResolvedValue({ tickets: [], total: 0 });
    render(<ApprovalsQueueScreen />);

    fireEvent.click(await screen.findByTestId('tab-approved'));

    expect(await screen.findByText('No approved requests yet')).toBeInTheDocument();
  });

  it('disables a decision while its request is in flight', async () => {
    let resolveApprove: (value: {
      ticketId: string;
      status: 'approved';
      reviewedBy: string;
      processedAt: string;
    }) => void = () => {};
    vi.mocked(AegisApi.approveTicket).mockReturnValue(
      new Promise((resolve) => {
        resolveApprove = resolve;
      })
    );

    render(<ApprovalsQueueScreen />);
    const approve = await screen.findByTestId('approve-button-appr-401');
    fireEvent.click(approve);

    await waitFor(() => expect(approve).toBeDisabled());

    resolveApprove({
      ticketId: 'appr-401',
      status: 'approved',
      reviewedBy: 'operator@example.com',
      processedAt: new Date().toISOString(),
    });
    await act(async () => {});
  });

  it('shows the screen error state when the queue cannot be read', async () => {
    vi.mocked(AegisApi.getPendingApprovals).mockRejectedValue(new Error('Gateway unavailable'));

    render(<ApprovalsQueueScreen />);

    expect(await screen.findByTestId('error-state')).toHaveTextContent('Gateway unavailable');
  });

  it('surfaces an approval failure in place instead of a browser alert', async () => {
    vi.mocked(AegisApi.approveTicket).mockRejectedValue(new Error('Ticket already resolved'));

    render(<ApprovalsQueueScreen />);
    fireEvent.click(await screen.findByTestId('approve-button-appr-401'));

    expect(await screen.findByTestId('approval-action-error')).toHaveTextContent(
      'Ticket already resolved'
    );
  });
});
