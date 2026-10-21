/**
 * Specification Anchors: FEAT-001, FEAT-004, FEAT-005, FEAT-008, C-002
 * Live Traffic Inspector Screen Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { LiveInspectorScreen } from '../screens/LiveInspectorScreen';
import { AegisApi } from '../services/api';
import { InspectorEvent } from '../types/contracts';

describe('LiveInspectorScreen Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders streaming events and toggles pause/resume', async () => {
    render(<LiveInspectorScreen />);

    // Initial event rows displayed in streaming table
    expect(await screen.findByTestId('event-row-evt-1001')).toBeInTheDocument();
    expect(screen.getByTestId('event-row-evt-1002')).toBeInTheDocument();

    // Pause toggle
    const pauseBtn = screen.getByTestId('stream-pause-toggle');
    expect(pauseBtn).toHaveTextContent('Pause');

    fireEvent.click(pauseBtn);
    expect(pauseBtn).toHaveTextContent('Resume Stream');

    fireEvent.click(pauseBtn);
    expect(pauseBtn).toHaveTextContent('Pause');
  });

  it('clears buffer and renders empty state', async () => {
    render(<LiveInspectorScreen />);

    const clearBtn = await screen.findByTestId('clear-buffer-button');
    fireEvent.click(clearBtn);

    expect(screen.getByTestId('empty-state')).toBeInTheDocument();
    expect(screen.getByText('Waiting for agent tool activity...')).toBeInTheDocument();
  });

  it('filters streaming events by search query', async () => {
    render(<LiveInspectorScreen />);

    const searchInput = screen.getByPlaceholderText(/Filter tool, agent, or event ID/i);
    fireEvent.change(searchInput, { target: { value: 'bash_run_command' } });

    expect(screen.getByTestId('event-row-evt-1002')).toBeInTheDocument();
    expect(screen.queryByTestId('event-row-evt-1001')).not.toBeInTheDocument();
  });

  it('filters events by security status verdict', async () => {
    render(<LiveInspectorScreen />);

    const statusSelect = screen.getByRole('combobox');
    fireEvent.change(statusSelect, { target: { value: 'BLOCKED' } });

    expect(screen.getByTestId('event-row-evt-1002')).toBeInTheDocument();
    expect(screen.queryByTestId('event-row-evt-1001')).not.toBeInTheDocument();
  });

  it('displays JSON payload viewer and redaction badges when selecting an event', async () => {
    render(<LiveInspectorScreen />);

    // Click on event with redactions (evt-1003)
    const pendingRow = screen.getByTestId('event-row-evt-1003');
    fireEvent.click(pendingRow);

    expect(await screen.findByTestId('redaction-badge')).toBeInTheDocument();
    expect(screen.getByText('1 DLP Redacted')).toBeInTheDocument();
    expect(screen.getByTestId('json-content')).toBeInTheDocument();
  });

  it('receives and appends incoming SSE events from AegisApi.subscribeToInspectorStream', async () => {
    let capturedCallback: ((e: InspectorEvent) => void) | null = null;
    vi.spyOn(AegisApi, 'subscribeToInspectorStream').mockImplementation((onEvent) => {
      capturedCallback = onEvent;
      return () => {};
    });

    render(<LiveInspectorScreen />);

    // Simulate incoming SSE event frame
    const newEvt: InspectorEvent = {
      eventId: 'evt-sse-999',
      timestamp: new Date().toISOString(),
      agentId: 'spiffe://aegis.internal/ns/test/sa/worker',
      toolName: 'k8s_scale_deployment',
      verdict: 'ALLOWED',
      latencyMs: 1.5,
      payloadSummary: '{"replicas": 5}',
    };

    act(() => {
      capturedCallback!(newEvt);
    });

    await waitFor(() => {
      expect(screen.getByTestId('event-row-evt-sse-999')).toBeInTheDocument();
    });
  });
});
