/**
 * Specification Anchors: FEAT-001, FEAT-004, FEAT-005, FEAT-008, C-002, C-003
 * Screen 2: Live Traffic Inspector. Frames arrive from the gateway event
 * stream; the buffer starts empty and a dropped stream is shown as such.
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  Play,
  Pause,
  Trash2,
  Search,
  Filter,
  Activity,
  RotateCw,
  X,
  ExternalLink,
  WifiOff,
} from 'lucide-react';
import { AegisApi } from '../services/api';
import { EventDecision, InspectorEvent, StreamStatus } from '../types/contracts';
import { StatusPill } from '../components/StatusPill';
import { JsonViewer } from '../components/JsonViewer';
import { EmptyState } from '../components/EmptyState';

interface LiveInspectorScreenProps {
  /** Re-fetches the pending approval queue after the stream reconnects. */
  onReconnected?: () => void;
  /** Applies a C-002 system event to the shell posture and approval badge. */
  onSystemEvent?: (status: 'NORMAL' | 'ELEVATED' | 'LOCKDOWN', pendingApprovals: number) => void;
  /** Refreshes the approval badge when a ticket is created or resolved. */
  onApprovalEvent?: () => void;
}

export const LiveInspectorScreen: React.FC<LiveInspectorScreenProps> = ({
  onReconnected,
  onSystemEvent,
  onApprovalEvent,
}) => {
  const [events, setEvents] = useState<InspectorEvent[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<InspectorEvent | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<StreamStatus>('connecting');
  const [streamError, setStreamError] = useState<string | null>(null);
  const [retryNonce, setRetryNonce] = useState(0);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const pausedRef = useRef(isPaused);
  const tableBottomRef = useRef<HTMLDivElement>(null);
  pausedRef.current = isPaused;

  useEffect(() => {
    const unsubscribe = AegisApi.subscribeToTrafficStream({
      onEvent: (newEvent) => {
        if (pausedRef.current) return;
        setEvents((previous) => [newEvent, ...previous].slice(0, 500));
      },
      onStatus: (status) => {
        setConnectionStatus(status);
        if (status === 'connected') setStreamError(null);
      },
      onError: (message) => setStreamError(message),
      onReconnected: () => onReconnected?.(),
      onApproval: () => onApprovalEvent?.(),
      onSystem: (event) => onSystemEvent?.(event.status, event.pendingApprovals),
    });

    return () => unsubscribe();
  }, [retryNonce, onReconnected, onSystemEvent, onApprovalEvent]);

  useEffect(() => {
    if (autoScroll && tableBottomRef.current) {
      tableBottomRef.current.scrollIntoView?.({ block: 'end' });
    }
  }, [events, autoScroll]);

  const handleClearBuffer = () => {
    setEvents([]);
    setSelectedEvent(null);
  };

  const filteredEvents = events.filter((event) => {
    const matchesSearch =
      searchQuery === '' ||
      event.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.agentId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      event.eventId.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus = statusFilter === 'ALL' || event.decision === (statusFilter as EventDecision);

    return matchesSearch && matchesStatus;
  });

  const isDisconnected = connectionStatus === 'disconnected' || !!streamError;

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col bg-grey-50 overflow-hidden animate-in fade-in duration-150">
      {connectionStatus === 'reconnecting' && (
        <div
          data-testid="reconnecting-banner"
          className="bg-warning-500/20 border-b border-warning-500 text-warning-900 px-space-md py-1.5 flex items-center justify-between text-xs font-mono"
        >
          <div className="flex items-center gap-2">
            <RotateCw className="w-3.5 h-3.5 animate-spin text-warning-500" />
            <span>Reconnecting to the live traffic stream…</span>
          </div>
          <span className="text-[11px] text-grey-500">Automatic retry is active</span>
        </div>
      )}

      {isDisconnected && connectionStatus !== 'reconnecting' && (
        <div
          data-testid="stream-error-banner"
          role="alert"
          className="bg-error-100 border-b border-error-300 text-error-900 px-space-md py-2 flex flex-wrap items-center justify-between gap-2 text-xs"
        >
          <div className="flex items-center gap-2">
            <WifiOff className="w-4 h-4 text-error-500" />
            <span>
              {streamError || 'The live traffic stream is disconnected.'} Events received before
              the drop are kept below.
            </span>
          </div>
          <button
            onClick={() => setRetryNonce((value) => value + 1)}
            data-testid="reconnect-stream-button"
            className="px-space-sm py-1 rounded-radius-sm bg-error-500 hover:bg-error-700 text-grey-900 font-semibold"
          >
            Reconnect stream
          </button>
        </div>
      )}

      <div className="p-space-md bg-grey-100 border-b border-grey-300 flex flex-wrap items-center justify-between gap-space-md">
        <div className="flex items-center gap-space-sm">
          <button
            onClick={() => setIsPaused(!isPaused)}
            data-testid="stream-pause-toggle"
            className={`inline-flex items-center gap-1.5 px-space-md py-1.5 rounded-radius-md text-xs font-bold transition-colors ${
              isPaused
                ? 'bg-primary-500 hover:bg-primary-600 text-grey-900'
                : 'bg-grey-200 hover:bg-grey-300 text-grey-800'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause'}</span>
          </button>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            data-testid="autoscroll-toggle"
            className={`px-space-sm py-1.5 rounded-radius-md text-xs font-mono font-medium transition-colors ${
              autoScroll ? 'bg-grey-200 text-primary-500' : 'bg-grey-200 text-grey-500'
            }`}
          >
            Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
          </button>

          <div className="flex items-center gap-2 px-space-sm py-1 bg-grey-200 border border-grey-300 rounded-radius-md text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-radius-full ${
                isPaused
                  ? 'bg-warning-500'
                  : connectionStatus === 'connected'
                  ? 'bg-success-500 animate-pulse'
                  : 'bg-error-500'
              }`}
            />
            <span className="text-grey-700">
              {isPaused ? 'PAUSED' : connectionStatus.toUpperCase()}
            </span>
            <span className="text-grey-500 pl-1 border-l border-grey-300">
              {events.length} frames
            </span>
          </div>

          <button
            onClick={handleClearBuffer}
            data-testid="clear-buffer-button"
            className="p-1.5 rounded-radius-md text-grey-500 hover:text-error-500 hover:bg-grey-200 transition-colors"
            title="Clear the event buffer"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-grey-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Filter tool, agent, or event ID..."
              className="pl-8 pr-space-md py-1.5 bg-grey-200 border border-grey-300 rounded-radius-md text-xs text-grey-900 placeholder:text-grey-500 focus:border-primary-500 outline-none w-64"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1 text-xs">
            <Filter className="w-3.5 h-3.5 text-grey-500" />
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
              className="bg-transparent text-grey-800 outline-none cursor-pointer"
            >
              <option value="ALL">All Decisions</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
              <option value="PENDING_APPROVAL">Pending HITL</option>
            </select>
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden relative">
        <div
          className={`flex-1 overflow-y-auto border-r border-grey-300 bg-grey-50 ${
            selectedEvent ? 'hidden lg:block' : 'block'
          }`}
        >
          {filteredEvents.length === 0 ? (
            <div className="p-space-lg">
              {events.length === 0 ? (
                <EmptyState
                  icon={connectionStatus === 'connected' ? Activity : WifiOff}
                  title={
                    connectionStatus === 'connected'
                      ? 'Waiting for agent tool activity...'
                      : 'No traffic received yet'
                  }
                  description={
                    connectionStatus === 'connected'
                      ? 'Tool calls passing through the gateway will appear here as they happen.'
                      : 'Reconnect the stream to start receiving tool calls from the gateway.'
                  }
                  actionLabel={
                    connectionStatus === 'connected' ? undefined : 'Reconnect stream'
                  }
                  onAction={
                    connectionStatus === 'connected'
                      ? undefined
                      : () => setRetryNonce((value) => value + 1)
                  }
                />
              ) : (
                <EmptyState
                  title="No matching events found"
                  description="No event frames match the current search and decision filters."
                  actionLabel="Reset Filters"
                  onAction={() => {
                    setSearchQuery('');
                    setStatusFilter('ALL');
                  }}
                />
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[500px] text-left text-xs font-mono">
                <thead className="bg-grey-100 border-b border-grey-300 text-grey-500 sticky top-0 z-10">
                  <tr>
                    <th className="py-2.5 px-space-md font-medium">Time (UTC)</th>
                    <th className="py-2.5 px-space-md font-medium">Decision</th>
                    <th className="py-2.5 px-space-md font-medium">Agent Workload</th>
                    <th className="py-2.5 px-space-md font-medium">Target Tool</th>
                    <th className="py-2.5 px-space-md font-medium">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-grey-300/40">
                  {filteredEvents.map((event) => {
                    const isSelected = selectedEvent?.eventId === event.eventId;
                    return (
                      <tr
                        key={event.eventId}
                        data-testid={`event-row-${event.eventId}`}
                        onClick={() => setSelectedEvent(event)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-primary-500/10 border-l-2 border-primary-500'
                            : 'hover:bg-grey-100/60'
                        }`}
                      >
                        <td className="py-2 px-space-md text-grey-500 whitespace-nowrap">
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2 px-space-md whitespace-nowrap">
                          <StatusPill verdict={event.decision} />
                        </td>
                        <td
                          className="py-2 px-space-md text-grey-800 max-w-[140px] truncate"
                          title={event.agentId}
                        >
                          {event.agentId.split('/').pop()}
                        </td>
                        <td className="py-2 px-space-md font-semibold text-primary-700">
                          {event.toolName}
                        </td>
                        <td className="py-2 px-space-md text-grey-500 font-mono">
                          {event.latencyMs}ms
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div ref={tableBottomRef} />
        </div>

        <div
          className={`w-full lg:w-[480px] xl:w-[540px] border-t lg:border-t-0 lg:border-l border-grey-300 bg-grey-100 flex flex-col overflow-y-auto ${
            selectedEvent ? 'block' : 'hidden lg:flex'
          }`}
        >
          {selectedEvent ? (
            <div className="p-space-md space-y-space-md">
              <div className="flex items-center justify-between pb-space-sm border-b border-grey-300">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedEvent(null)}
                    className="lg:hidden p-1 text-grey-600 hover:text-grey-900 rounded-radius-sm"
                    aria-label="Back to event list"
                  >
                    ←
                  </button>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-grey-900">
                        {selectedEvent.eventId}
                      </span>
                      <StatusPill verdict={selectedEvent.decision} />
                    </div>
                    <p className="text-[11px] font-mono text-grey-500 mt-0.5">
                      {new Date(selectedEvent.timestamp).toISOString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 text-grey-500 hover:text-grey-900 rounded-radius-sm"
                  aria-label="Close details"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md text-xs font-mono space-y-1.5">
                <div>
                  <span className="text-grey-500">Agent SPIFFE ID: </span>
                  <span className="text-accent-500 break-all">{selectedEvent.agentId}</span>
                </div>
                <div>
                  <span className="text-grey-500">Tool invoked: </span>
                  <span className="text-primary-700 font-semibold">{selectedEvent.toolName}</span>
                </div>
                {selectedEvent.matchedRuleIds.length > 0 && (
                  <div>
                    <span className="text-grey-500">Matched rules: </span>
                    <span className="text-grey-800">{selectedEvent.matchedRuleIds.join(', ')}</span>
                  </div>
                )}
                <div>
                  <span className="text-grey-500">Execution latency: </span>
                  <span className="text-success-500">{selectedEvent.latencyMs} ms</span>
                </div>
              </div>

              <JsonViewer
                title="Intercepted Tool Arguments"
                data={selectedEvent.arguments}
                redactions={selectedEvent.redactions}
              />
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-space-lg text-center text-grey-500 text-xs">
              <ExternalLink className="w-8 h-8 mb-2 opacity-50" />
              <span>
                Select an event row to inspect the intercepted arguments and the security
                decision.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
