/**
 * Specification Anchors: FEAT-006, FEAT-008, C-003, C-004, C-014, C-019
 * Screen 3: Approvals Queue. Pending tickets come from C-003, history from
 * C-019, and decisions post to C-004 or C-014. The reviewer identity is taken
 * from the verified operator token by the gateway, never from the console.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { Clock, AlertTriangle, Check, X, Loader2, Inbox } from 'lucide-react';
import { AegisApi } from '../services/api';
import {
  ApprovalHistoryStatus,
  ApprovalHistoryTicket,
  ApprovalTicket,
} from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { JsonViewer } from '../components/JsonViewer';

type Tab = 'pending' | ApprovalHistoryStatus;

interface DisplayTicket {
  id: string;
  agentId: string;
  toolName: string;
  argumentsPayload: string;
  triggerPolicyId: string;
  agentIntent: string | null;
  status: string;
  createdAt: string;
  expiresAt: string;
  reviewedBy: string | null;
  rejectionReason: string | null;
  processedAt: string | null;
}

function fromPending(ticket: ApprovalTicket): DisplayTicket {
  return {
    ...ticket,
    reviewedBy: null,
    rejectionReason: null,
    processedAt: null,
  };
}

function fromHistory(ticket: ApprovalHistoryTicket): DisplayTicket {
  return {
    ...ticket,
    agentIntent: null,
  };
}

/** The contract carries arguments as JSON text already masked by the gateway. */
function parseArguments(payload: string): unknown {
  try {
    return JSON.parse(payload);
  } catch {
    return payload;
  }
}

interface ApprovalsQueueScreenProps {
  /** C-003, C-004, and C-014 admit admin and operator; auditors read history only. */
  canReviewPending?: boolean;
}

export const ApprovalsQueueScreen: React.FC<ApprovalsQueueScreenProps> = ({
  canReviewPending = true,
}) => {
  const [activeTab, setActiveTab] = useState<Tab>(canReviewPending ? 'pending' : 'approved');
  const [tickets, setTickets] = useState<DisplayTicket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [rejectingTicket, setRejectingTicket] = useState<DisplayTicket | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const loadApprovals = useCallback(async (tab: Tab = activeTab) => {
    setLoading(true);
    setError(null);
    try {
      if (tab === 'pending') {
        const response = await AegisApi.getPendingApprovals(100);
        setTickets(response.tickets.map(fromPending));
      } else {
        const response = await AegisApi.getApprovalHistory(tab, 100, 0);
        setTickets(response.tickets.map(fromHistory));
      }
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve the approval queue');
    }
  }, [activeTab]);

  useEffect(() => {
    loadApprovals(activeTab);
  }, [activeTab, loadApprovals]);

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  const handleApprove = async (ticket: DisplayTicket) => {
    setActionLoadingId(ticket.id);
    setActionError(null);
    try {
      await AegisApi.approveTicket(ticket.id);
      await loadApprovals('pending');
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'The approval could not be submitted.');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleReject = async () => {
    if (!rejectingTicket) return;
    setActionLoadingId(rejectingTicket.id);
    setActionError(null);
    try {
      await AegisApi.rejectTicket(rejectingTicket.id, rejectReason.trim());
      setRejectingTicket(null);
      setRejectReason('');
      await loadApprovals('pending');
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : 'The rejection could not be submitted.');
    } finally {
      setActionLoadingId(null);
    }
  };

  const getRemainingTime = (expiresAt: string) => {
    const difference = Math.max(0, new Date(expiresAt).getTime() - now);
    const minutes = Math.floor(difference / 60000);
    const seconds = Math.floor((difference % 60000) / 1000);
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  };

  const emptyCopy =
    activeTab === 'pending'
      ? {
          title: 'No agent actions are waiting for approval',
          description:
            'Requests appear here when a gateway policy routes an autonomous call to a human decision.',
        }
      : activeTab === 'approved'
      ? {
          title: 'No approved requests yet',
          description: 'Approved approvals will be recorded here with the reviewer identity.',
        }
      : {
          title: 'No rejected requests yet',
          description: 'Rejected approvals will be recorded here with the rejection reason.',
        };

  // A pending ticket whose TTL reaches zero fails closed at the gateway, so it
  // leaves this queue as soon as its countdown expires (screens/03).
  const expiredCount =
    activeTab === 'pending'
      ? tickets.filter((ticket) => new Date(ticket.expiresAt).getTime() <= now).length
      : 0;
  const displayedTickets =
    activeTab === 'pending'
      ? tickets.filter((ticket) => new Date(ticket.expiresAt).getTime() > now)
      : tickets;

  return (
    <div className="p-space-lg max-w-5xl mx-auto space-y-space-md animate-in fade-in duration-150">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-space-md border-b border-grey-300 gap-space-sm">
        <div>
          <h2 className="text-h2 font-bold text-grey-900">Human-in-the-Loop Approvals</h2>
          <p className="text-caption text-grey-500">
            Authorize or reject high-risk autonomous agent tool invocations before execution
          </p>
        </div>

        <div className="flex items-center gap-1 bg-grey-100 p-1 rounded-radius-md border border-grey-300 text-caption">
          {canReviewPending && (
            <button
              onClick={() => setActiveTab('pending')}
              data-testid="tab-pending"
              className={`px-space-md py-1 rounded-radius-sm font-semibold transition-colors ${
                activeTab === 'pending'
                  ? 'bg-primary-500 text-grey-900'
                  : 'text-grey-600 hover:text-grey-900'
              }`}
            >
              Pending
            </button>
          )}
          <button
            onClick={() => setActiveTab('approved')}
            data-testid="tab-approved"
            className={`px-space-md py-1 rounded-radius-sm font-semibold transition-colors ${
              activeTab === 'approved'
                ? 'bg-primary-500 text-grey-900'
                : 'text-grey-600 hover:text-grey-900'
            }`}
          >
            Approved History
          </button>
          <button
            onClick={() => setActiveTab('rejected')}
            data-testid="tab-rejected"
            className={`px-space-md py-1 rounded-radius-sm font-semibold transition-colors ${
              activeTab === 'rejected'
                ? 'bg-primary-500 text-grey-900'
                : 'text-grey-600 hover:text-grey-900'
            }`}
          >
            Rejected History
          </button>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={() => loadApprovals(activeTab)} />}

      {actionError && (
        <div
          role="alert"
          data-testid="approval-action-error"
          className="p-space-sm bg-error-100 border border-error-300 text-error-900 rounded-radius-md text-caption"
        >
          {actionError}
        </div>
      )}

      {expiredCount > 0 && (
        <div
          data-testid="expired-tickets-notice"
          role="status"
          className="p-space-sm bg-warning-100 border border-warning-300 text-warning-900 rounded-radius-md text-caption"
        >
          {expiredCount === 1
            ? '1 request expired before a decision and left this queue.'
            : `${expiredCount} requests expired before a decision and left this queue.`}{' '}
          The gateway failed them closed.
        </div>
      )}

      {loading ? (
        <div className="space-y-space-md">
          <Skeleton className="h-44 w-full" />
          <Skeleton className="h-44 w-full" />
        </div>
      ) : displayedTickets.length === 0 ? (
        expiredCount > 0 ? null : (
          <EmptyState icon={Inbox} title={emptyCopy.title} description={emptyCopy.description} />
        )
      ) : (
        <div className="space-y-space-md">
          {displayedTickets.map((ticket) => {
            const isActionLoading = actionLoadingId === ticket.id;
            return (
              <div
                key={ticket.id}
                data-testid={`approval-ticket-${ticket.id}`}
                className="bg-grey-100 border border-grey-300 rounded-radius-lg p-space-md space-y-space-md shadow-sm"
              >
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-space-sm border-b border-grey-300 gap-space-sm">
                  <div className="flex items-center gap-space-sm flex-wrap">
                    <span className="font-mono text-caption font-bold text-grey-900">{ticket.id}</span>
                    <span className="font-mono text-caption px-2 py-0.5 rounded-radius-sm bg-accent-100 text-accent-900 border border-accent-300">
                      {ticket.agentId.split('/').pop()}
                    </span>
                    <span className="font-mono text-caption font-semibold text-primary-700">
                      {ticket.toolName}
                    </span>
                  </div>

                  <div className="flex items-center gap-space-sm flex-wrap">
                    <span className="text-caption font-mono text-grey-600 px-2 py-0.5 rounded-radius-sm bg-grey-200 border border-grey-300">
                      Trigger: {ticket.triggerPolicyId}
                    </span>

                    {activeTab === 'pending' && (
                      <span className="inline-flex items-center gap-1 text-caption font-mono text-warning-500 bg-warning-100/50 px-2 py-0.5 rounded-radius-sm border border-warning-300/40">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{getRemainingTime(ticket.expiresAt)} left</span>
                      </span>
                    )}

                    {ticket.status !== 'pending' && <StatusLabel status={ticket.status} />}
                  </div>
                </div>

                <div className="text-caption space-y-1">
                  {ticket.agentIntent && (
                    <div className="text-grey-600">
                      <span className="font-semibold text-grey-500">Agent stated intent: </span>
                      <span>{ticket.agentIntent}</span>
                    </div>
                  )}
                  <div className="text-grey-500">
                    Requested {new Date(ticket.createdAt).toLocaleString()} · expires{' '}
                    {new Date(ticket.expiresAt).toLocaleString()}
                  </div>
                  {ticket.reviewedBy && (
                    <div className="text-grey-600">
                      <span className="font-semibold text-grey-500">Reviewed by: </span>
                      <span className="font-mono">{ticket.reviewedBy}</span>
                      {ticket.processedAt && (
                        <span className="text-grey-500">
                          {' '}
                          · {new Date(ticket.processedAt).toLocaleString()}
                        </span>
                      )}
                    </div>
                  )}
                  {ticket.rejectionReason && (
                    <div className="flex items-start gap-1 text-error-700 font-medium">
                      <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                      <span>{ticket.rejectionReason}</span>
                    </div>
                  )}
                </div>

                <JsonViewer
                  title="Suspended Execution Arguments"
                  data={parseArguments(ticket.argumentsPayload)}
                />

                {activeTab === 'pending' && (
                  <div className="flex items-center justify-end gap-space-sm pt-space-xs border-t border-grey-300">
                    <button
                      onClick={() => {
                        setRejectingTicket(ticket);
                        setRejectReason('');
                        setActionError(null);
                      }}
                      disabled={isActionLoading}
                      data-testid={`reject-button-${ticket.id}`}
                      className="inline-flex items-center gap-1.5 px-space-md py-space-sm rounded-radius-md text-caption font-semibold border border-error-300 text-error-700 hover:bg-error-100 hover:text-error-900 transition-colors disabled:opacity-50"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>

                    <button
                      onClick={() => handleApprove(ticket)}
                      disabled={isActionLoading}
                      data-testid={`approve-button-${ticket.id}`}
                      className="inline-flex items-center gap-1.5 px-space-lg py-space-sm rounded-radius-md text-caption font-bold bg-success-500 hover:bg-success-700 text-grey-50 transition-colors shadow-sm disabled:opacity-50"
                    >
                      {isActionLoading ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Check className="w-3.5 h-3.5" />
                      )}
                      <span>Approve Request</span>
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {rejectingTicket && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="reject-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-md bg-grey-100 border border-error-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <h3 id="reject-dialog-title" className="font-bold text-body-small text-error-900">
                Reject Approval Ticket
              </h3>
              <button
                onClick={() => setRejectingTicket(null)}
                className="p-1 text-grey-500 hover:text-grey-900"
                aria-label="Close rejection dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-caption text-grey-600">
              Provide a rejection reason. The gateway records it in the audit ledger and returns it
              to the requesting agent.
            </p>

            <textarea
              value={rejectReason}
              onChange={(event) => setRejectReason(event.target.value)}
              required
              rows={3}
              data-testid="rejection-reason-input"
              className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-space-sm py-2 text-caption text-grey-900 focus:border-error-500 outline-none resize-none"
              placeholder="Explain why this request is denied..."
            />

            <div className="flex items-center justify-end gap-space-sm pt-space-xs">
              <button
                type="button"
                onClick={() => setRejectingTicket(null)}
                className="px-space-md py-space-sm rounded-radius-md text-caption text-grey-600 hover:text-grey-900"
              >
                Cancel
              </button>
              <button
                type="button"
                data-testid="confirm-reject-button"
                disabled={!rejectReason.trim() || actionLoadingId === rejectingTicket.id}
                onClick={handleReject}
                className="px-space-md py-space-sm rounded-radius-md text-caption font-bold bg-error-500 hover:bg-error-700 text-grey-900 transition-colors disabled:opacity-50"
              >
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const StatusLabel: React.FC<{ status: string }> = ({ status }) => (
  <span className="inline-flex items-center px-2 py-0.5 rounded-radius-full text-caption font-mono font-bold uppercase bg-grey-200 text-grey-700 border border-grey-300">
    {status}
  </span>
);
