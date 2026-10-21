/**
 * Specification Anchors: FEAT-001, FEAT-004, FEAT-005, FEAT-008, C-002
 * Screen 2: Live Traffic Inspector
 */

import React, { useEffect, useState, useRef } from 'react';
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
} from 'lucide-react';
import { AegisApi, MOCK_STREAM_EVENTS } from '../services/api';
import { InspectorEvent, EventVerdict } from '../types/contracts';
import { StatusPill } from '../components/StatusPill';
import { JsonViewer } from '../components/JsonViewer';
import { EmptyState } from '../components/EmptyState';

export const LiveInspectorScreen: React.FC = () => {
  const [events, setEvents] = useState<InspectorEvent[]>(MOCK_STREAM_EVENTS);
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<InspectorEvent | null>(MOCK_STREAM_EVENTS[0]);
  const [connectionStatus, setConnectionStatus] = useState<
    'connecting' | 'connected' | 'reconnecting' | 'disconnected'
  >('connected');

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [agentFilter, setAgentFilter] = useState<string>('ALL');

  const tableBottomRef = useRef<HTMLDivElement>(null);

  // Subscribe to C-002 SSE stream
  useEffect(() => {
    const unsubscribe = AegisApi.subscribeToInspectorStream(
      (newEvent) => {
        if (!isPaused) {
          setEvents((prev) => {
            const next = [newEvent, ...prev];
            return next.slice(0, 500); // Buffer up to 500 events
          });
        }
      },
      (status) => {
        setConnectionStatus(status);
      }
    );

    return () => {
      unsubscribe();
    };
  }, [isPaused]);

  // Auto-scroll when new events arrive
  useEffect(() => {
    if (autoScroll && tableBottomRef.current) {
      // Smooth scroll if auto-scroll is engaged
    }
  }, [events, autoScroll]);

  const handleClearBuffer = () => {
    setEvents([]);
    setSelectedEvent(null);
  };

  const filteredEvents = events.filter((e) => {
    const matchesSearch =
      searchQuery === '' ||
      e.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.agentId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.eventId.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === 'ALL' || e.verdict === (statusFilter as EventVerdict);

    const matchesAgent =
      agentFilter === 'ALL' || e.agentId.includes(agentFilter);

    return matchesSearch && matchesStatus && matchesAgent;
  });

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col bg-grey-50 overflow-hidden animate-in fade-in duration-150">
      {/* 1. Reconnecting Alert Banner if disconnected */}
      {connectionStatus === 'reconnecting' && (
        <div
          data-testid="reconnecting-banner"
          className="bg-warning-500/20 border-b border-warning-500 text-warning-900 px-space-md py-1.5 flex items-center justify-between text-xs font-mono"
        >
          <div className="flex items-center gap-2">
            <RotateCw className="w-3.5 h-3.5 animate-spin text-warning-500" />
            <span>Reconnecting to live traffic stream (GET /api/v1/inspector/events)...</span>
          </div>
          <span className="text-[11px] text-grey-500">Auto-retry active</span>
        </div>
      )}

      {/* 2. Stream Control Toolbar */}
      <div className="p-space-md bg-grey-100 border-b border-grey-300 flex flex-wrap items-center justify-between gap-space-md">
        <div className="flex items-center gap-space-sm">
          {/* Pause / Play */}
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

          {/* Auto-scroll toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            data-testid="autoscroll-toggle"
            className={`px-space-sm py-1.5 rounded-radius-md text-xs font-mono font-medium transition-colors ${
              autoScroll
                ? 'bg-grey-200 text-primary-500'
                : 'bg-grey-200 text-grey-500'
            }`}
          >
            Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
          </button>

          {/* Buffer counter & status */}
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

          {/* Clear buffer */}
          <button
            onClick={handleClearBuffer}
            data-testid="clear-buffer-button"
            className="p-1.5 rounded-radius-md text-grey-500 hover:text-error-500 hover:bg-grey-200 transition-colors"
            title="Clear Event Buffer"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>

        {/* Filter inputs */}
        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-grey-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter tool, agent, or event ID..."
              className="pl-8 pr-space-md py-1.5 bg-grey-200 border border-grey-300 rounded-radius-md text-xs text-grey-900 placeholder:text-grey-500 focus:border-primary-500 outline-none w-64"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-grey-200 border border-grey-300 rounded-radius-md px-2 py-1 text-xs">
            <Filter className="w-3.5 h-3.5 text-grey-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
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

      {/* 3. Master-Detail Split Workspace */}
      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden relative">
        {/* Left Table Panel */}
        <div className={`flex-1 overflow-y-auto border-r border-grey-300 bg-grey-50 ${selectedEvent ? 'hidden lg:block' : 'block'}`}>
          {filteredEvents.length === 0 ? (
            <div className="p-space-lg">
              {events.length === 0 ? (
                <EmptyState
                  icon={Activity}
                  title="Waiting for agent tool activity..."
                  description="Incoming JSON-RPC 2.0 tool calls passing through the AegisMCP gateway will stream here in real time."
                />
              ) : (
                <EmptyState
                  title="No matching events found"
                  description="No streaming event frames match your active search and status filters."
                  actionLabel="Reset Filters"
                  onAction={() => {
                    setSearchQuery('');
                    setStatusFilter('ALL');
                    setAgentFilter('ALL');
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
                    <th className="py-2.5 px-space-md font-medium">Status</th>
                    <th className="py-2.5 px-space-md font-medium">Agent Workload</th>
                    <th className="py-2.5 px-space-md font-medium">Target Tool</th>
                    <th className="py-2.5 px-space-md font-medium">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-grey-300/40">
                  {filteredEvents.map((evt) => {
                    const isSelected = selectedEvent?.eventId === evt.eventId;
                    return (
                      <tr
                        key={evt.eventId}
                        data-testid={`event-row-${evt.eventId}`}
                        onClick={() => setSelectedEvent(evt)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-primary-500/10 border-l-2 border-primary-500'
                            : 'hover:bg-grey-100/60'
                        }`}
                      >
                        <td className="py-2 px-space-md text-grey-500 whitespace-nowrap">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2 px-space-md whitespace-nowrap">
                          <StatusPill verdict={evt.verdict} />
                        </td>
                        <td
                          className="py-2 px-space-md text-grey-800 max-w-[140px] truncate"
                          title={evt.agentId}
                        >
                          {evt.agentId.split('/').pop()}
                        </td>
                        <td className="py-2 px-space-md font-semibold text-primary-700">
                          {evt.toolName}
                        </td>
                        <td className="py-2 px-space-md text-grey-500 font-mono">
                          {evt.latencyMs}ms
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

        {/* Right Inspection Drawer Panel */}
        <div className={`w-full lg:w-[480px] xl:w-[540px] border-t lg:border-t-0 lg:border-l border-grey-300 bg-grey-100 flex flex-col overflow-y-auto ${selectedEvent ? 'block' : 'hidden lg:flex'}`}>
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
                      <StatusPill verdict={selectedEvent.verdict} />
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

              {/* Event Metadata card */}
              <div className="p-space-sm bg-grey-200 border border-grey-300 rounded-radius-md text-xs font-mono space-y-1.5">
                <div>
                  <span className="text-grey-500">Agent SPIFFE ID: </span>
                  <span className="text-accent-500 break-all">{selectedEvent.agentId}</span>
                </div>
                <div>
                  <span className="text-grey-500">Tool Invoked: </span>
                  <span className="text-primary-700 font-semibold">{selectedEvent.toolName}</span>
                </div>
                {selectedEvent.matchedPolicyRule && (
                  <div>
                    <span className="text-grey-500">Matched Policy: </span>
                    <span className="text-grey-800">{selectedEvent.matchedPolicyRule}</span>
                  </div>
                )}
                <div>
                  <span className="text-grey-500">Execution Latency: </span>
                  <span className="text-success-500">{selectedEvent.latencyMs} ms</span>
                </div>
              </div>

              {/* JSON-RPC Request Viewer */}
              <div>
                <JsonViewer
                  title="JSON-RPC Request AST"
                  data={
                    selectedEvent.rawRequest || {
                      jsonrpc: '2.0',
                      id: selectedEvent.eventId,
                      method: 'tools/call',
                      params: {
                        name: selectedEvent.toolName,
                        arguments: JSON.parse(selectedEvent.payloadSummary || '{}'),
                      },
                    }
                  }
                  redactions={selectedEvent.redactions}
                />
              </div>

              {/* JSON-RPC Response Viewer */}
              {selectedEvent.rawResponse && (
                <div>
                  <JsonViewer
                    title="JSON-RPC Response"
                    data={selectedEvent.rawResponse}
                  />
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center p-space-lg text-center text-grey-500 text-xs">
              <ExternalLink className="w-8 h-8 mb-2 opacity-50" />
              <span>Select any event row from the live stream to inspect formatted JSON-RPC payloads and security decisions.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
