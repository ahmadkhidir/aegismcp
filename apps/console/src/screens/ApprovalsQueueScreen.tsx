/**
 * Specification Anchors: FEAT-006, FEAT-008, C-003, C-004
 * Screen 3: Approvals Queue
 */

import React, { useEffect, useState } from 'react';
import {
  Clock,
  AlertTriangle,
  Check,
  X,
  Loader2,
  Inbox,
} from 'lucide-react';
import { AegisApi } from '../services/api';
import { ApprovalTicket } from '../types/contracts';
import { Skeleton } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { JsonViewer } from '../components/JsonViewer';

export const ApprovalsQueueScreen: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'pending' | 'approved' | 'rejected'>('pending');
  const [tickets, setTickets] = useState<ApprovalTicket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Rejection modal state
  const [rejectingTicket, setRejectingTicket] = useState<ApprovalTicket | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);

  const loadApprovals = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await AegisApi.getApprovals(activeTab);
      setTickets(res.tickets);
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(err instanceof Error ? err.message : 'Failed to retrieve approval queue');
    }
  };

  useEffect(() => {
    loadApprovals();
  }, [activeTab]);

  const handleDecision = async (
    ticketId: string,
    decision: 'APPROVE' | 'REJECT',
    reason = 'Approved by administrator console operator'
  ) => {
    setActionLoadingId(ticketId);
    try {
      await AegisApi.submitApprovalDecision(ticketId, {
        decision,
        reviewer: 'elena.rostova@aegis.internal',
        reason,
      });
      // Remove ticket from local view
      setTickets((prev) => prev.filter((t) => t.id !== ticketId));
      setActionLoadingId(null);
      setRejectingTicket(null);
      setRejectReason('');
    } catch (err: unknown) {
      setActionLoadingId(null);
      alert(err instanceof Error ? err.message : 'Failed to submit decision');
    }
  };

  const getRemainingTime = (expiresAt: string) => {
    const diff = Math.max(0, new Date(expiresAt).getTime() - Date.now());
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  return (
    <div className="p-space-lg max-w-5xl mx-auto space-y-space-md animate-in fade-in duration-150">
      {/* Header & Tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-space-md border-b border-grey-300 gap-space-sm">
        <div>
          <h2 className="text-xl font-bold text-grey-900">Human-in-the-Loop Approvals</h2>
          <p className="text-xs text-grey-500">
            Authorize or reject high-risk autonomous agent tool invocations before execution
          </p>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center gap-1 bg-grey-100 p-1 rounded-radius-md border border-grey-300 text-xs">
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

      {error && <ErrorState message={error} onRetry={loadApprovals} />}

      {/* Loading Skeleton */}
      {loading ? (
        <div className="space-y-space-md">
          <Skeleton className="h-44 w-full" />
          <Skeleton className="h-44 w-full" />
        </div>
      ) : tickets.length === 0 ? (
        <EmptyState
          icon={Inbox}
          title="All clear — no pending agent actions requiring human approval"
          description="Autonomous agent requests will appear here when policy rules flag elevated risk scores or sensitive tool execution."
        />
      ) : (
        <div className="space-y-space-md">
          {tickets.map((ticket) => {
            const isActionLoading = actionLoadingId === ticket.id;
            return (
              <div
                key={ticket.id}
                data-testid={`approval-ticket-${ticket.id}`}
                className="bg-grey-100 border border-grey-300 rounded-radius-lg p-space-md space-y-space-md shadow-sm"
              >
                {/* Ticket Header */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-space-sm border-b border-grey-300 gap-space-sm">
                  <div className="flex items-center gap-space-sm flex-wrap">
                    <span className="font-mono text-xs font-bold text-grey-900">
                      {ticket.id}
                    </span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded-radius-sm bg-accent-100 text-accent-900 border border-accent-300">
                      {ticket.agentId.split('/').pop()}
                    </span>
                    <span className="font-mono text-xs font-semibold text-primary-700">
                      {ticket.toolName}
                    </span>
                  </div>

                  <div className="flex items-center gap-space-sm">
                    {/* Risk Score Pill */}
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded-radius-full ${
                        ticket.riskScore >= 80
                          ? 'bg-error-100 text-error-900 border border-error-300'
                          : 'bg-warning-100 text-warning-900 border border-warning-300'
                      }`}
                    >
                      Risk: {ticket.riskScore}/100
                    </span>

                    {/* TTL Countdown */}
                    {activeTab === 'pending' && (
                      <span className="inline-flex items-center gap-1 text-xs font-mono text-warning-500 bg-warning-100/50 px-2 py-0.5 rounded-radius-sm border border-warning-300/40">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{getRemainingTime(ticket.expiresAt)} left</span>
                      </span>
                    )}
                  </div>
                </div>

                {/* Reason & Agent Intent */}
                <div className="text-xs space-y-1">
                  <div className="flex items-start gap-1 text-error-700 font-medium">
                    <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                    <span>{ticket.reason}</span>
                  </div>
                  {ticket.agentIntent && (
                    <div className="text-grey-600 pl-4">
                      <span className="font-semibold text-grey-500">Agent Stated Intent: </span>
                      <span>{ticket.agentIntent}</span>
                    </div>
                  )}
                </div>

                {/* Parameter Diff / Viewer */}
                <div>
                  <JsonViewer
                    title="Suspended Execution Arguments"
                    data={ticket.arguments}
                  />
                </div>

                {/* Action Footer (for Pending items) */}
                {activeTab === 'pending' && (
                  <div className="flex items-center justify-end gap-space-sm pt-space-xs border-t border-grey-300">
                    <button
                      onClick={() => setRejectingTicket(ticket)}
                      disabled={isActionLoading}
                      data-testid={`reject-button-${ticket.id}`}
                      className="inline-flex items-center gap-1.5 px-space-md py-space-sm rounded-radius-md text-xs font-semibold border border-error-300 text-error-700 hover:bg-error-100 hover:text-error-900 transition-colors disabled:opacity-50"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>

                    <button
                      onClick={() =>
                        handleDecision(ticket.id, 'APPROVE', 'Authorized by SecOps lead')
                      }
                      disabled={isActionLoading}
                      data-testid={`approve-button-${ticket.id}`}
                      className="inline-flex items-center gap-1.5 px-space-lg py-space-sm rounded-radius-md text-xs font-bold bg-success-500 hover:bg-success-700 text-grey-50 transition-colors shadow-sm disabled:opacity-50"
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

      {/* Mandatory Rejection Reason Dialog (C-004) */}
      {rejectingTicket && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-space-md bg-grey-50/80 backdrop-blur-sm"
        >
          <div className="w-full max-w-md bg-grey-100 border border-error-300 rounded-radius-lg p-space-lg shadow-xl space-y-space-md">
            <div className="flex items-center justify-between pb-space-xs border-b border-grey-300">
              <h3 className="font-bold text-sm text-error-900">Reject Approval Ticket</h3>
              <button
                onClick={() => setRejectingTicket(null)}
                className="p-1 text-grey-500 hover:text-grey-900"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-grey-600">
              Provide an explanatory rejection reason that will be transmitted back to the agent in the JSON-RPC error payload:
            </p>

            <textarea
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              required
              rows={3}
              data-testid="rejection-reason-input"
              className="w-full bg-grey-200 border border-grey-300 rounded-radius-md px-space-sm py-2 text-xs text-grey-900 focus:border-error-500 outline-none resize-none"
              placeholder="e.g. Operation denied: Staging namespace deletion rejected during freeze..."
            />

            <div className="flex items-center justify-end gap-space-sm pt-space-xs">
              <button
                type="button"
                onClick={() => setRejectingTicket(null)}
                className="px-space-md py-space-sm rounded-radius-md text-xs text-grey-600 hover:text-grey-900"
              >
                Cancel
              </button>
              <button
                type="button"
                data-testid="confirm-reject-button"
                disabled={!rejectReason.trim() || actionLoadingId === rejectingTicket.id}
                onClick={() =>
                  handleDecision(rejectingTicket.id, 'REJECT', rejectReason)
                }
                className="px-space-md py-space-sm rounded-radius-md text-xs font-bold bg-error-500 hover:bg-error-400 text-grey-900 transition-colors disabled:opacity-50"
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
