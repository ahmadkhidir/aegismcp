/**
 * Specification Anchors: FEAT-008, NFR-005, C-002
 * Browser-side coverage of the C-002 event stream: named frames, heartbeat
 * comments, exponential backoff, reconnect notification, and terminal refusals.
 * The gateway's own stream behavior is covered by the artifact conformance test.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { subscribeToTrafficStream, TrafficStreamHandlers } from '../services/api';

const encoder = new TextEncoder();

interface FakeResponse {
  ok: boolean;
  status: number;
  body: {
    getReader: () => {
      read: () => Promise<{ value: Uint8Array | undefined; done: boolean }>;
      cancel: () => void;
    };
  };
  text: () => Promise<string>;
}

function streamResponse(chunks: string[], status = 200): FakeResponse {
  let index = 0;
  return {
    ok: status >= 200 && status < 300,
    status,
    body: {
      getReader: () => ({
        read: async () => {
          if (index < chunks.length) {
            return { value: encoder.encode(chunks[index++]), done: false };
          }
          return { value: undefined, done: true };
        },
        cancel: vi.fn(),
      }),
    },
    text: async () => chunks.join(''),
  };
}

function refuseResponse(status: number, body: string): FakeResponse {
  return {
    ok: false,
    status,
    body: {
      getReader: () => ({
        read: async () => ({ value: undefined, done: true }),
        cancel: vi.fn(),
      }),
    },
    text: async () => body,
  };
}

function collectHandlers() {
  const events: unknown[] = [];
  const approvals: unknown[] = [];
  const system: unknown[] = [];
  const statuses: string[] = [];
  const errors: string[] = [];
  const reconnected = vi.fn();

  const handlers: TrafficStreamHandlers = {
    onEvent: (event) => events.push(event),
    onApproval: (event) => approvals.push(event),
    onSystem: (event) => system.push(event),
    onStatus: (status) => statuses.push(status),
    onError: (message) => errors.push(message),
    onReconnected: reconnected,
  };

  return { handlers, events, approvals, system, statuses, errors, reconnected };
}

async function flushMicrotasks() {
  for (let index = 0; index < 10; index += 1) await Promise.resolve();
  await vi.advanceTimersByTimeAsync(0);
  for (let index = 0; index < 10; index += 1) await Promise.resolve();
}

describe('C-002 traffic stream subscription', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('parses traffic, approval, and system frames split across chunks', async () => {
    vi.useFakeTimers();
    const first = streamResponse([
      'retry: 3000\n\n: keepalive\n\nevent: traffic\ndata: {"eventId":"evt-1","timestamp":"2026-11-23T10:00:00Z",',
      '"agentId":"spiffe://example.org/ns/dev/sa/bot","toolName":"git_diff","arguments":{},"decision":"ALLOWED","latencyMs":1.2,"matchedRuleIds":["SEC-01"],"redactions":[]}\n\n',
      'event: approval\ndata: {"ticketId":"appr-1","status":"pending","expiresAt":"2026-11-23T10:05:00Z"}\n\n',
      'event: system\ndata: {"status":"ELEVATED","pendingApprovals":2}\n\n',
    ]);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(streamResponse([]));
    vi.stubGlobal('fetch', fetchMock);

    const capture = collectHandlers();
    const unsubscribe = subscribeToTrafficStream(capture.handlers);
    await flushMicrotasks();

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/stream/traffic',
      expect.objectContaining({ cache: 'no-store' })
    );
    expect(capture.statuses[0]).toBe('connecting');
    expect(capture.statuses).toContain('connected');
    expect(capture.events).toEqual([
      expect.objectContaining({ eventId: 'evt-1', toolName: 'git_diff', decision: 'ALLOWED' }),
    ]);
    expect(capture.approvals).toEqual([
      { ticketId: 'appr-1', status: 'pending', expiresAt: '2026-11-23T10:05:00Z' },
    ]);
    expect(capture.system).toEqual([{ status: 'ELEVATED', pendingApprovals: 2 }]);
    expect(capture.reconnected).not.toHaveBeenCalled();

    unsubscribe();
  });

  it('reconnects with exponential backoff and reports the reconnect', async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(streamResponse([': keepalive\n\n']))
      .mockResolvedValueOnce(streamResponse(['event: system\ndata: {"status":"NORMAL","pendingApprovals":0}\n\n']))
      .mockResolvedValueOnce(streamResponse([]));
    vi.stubGlobal('fetch', fetchMock);

    const capture = collectHandlers();
    const unsubscribe = subscribeToTrafficStream(capture.handlers);
    await flushMicrotasks();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(capture.statuses).toContain('reconnecting');
    expect(capture.reconnected).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(capture.reconnected).toHaveBeenCalledTimes(1);
    expect(capture.statuses).toContain('connected');

    unsubscribe();
  });

  it('does not retry a stream the gateway refused as unauthenticated', async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        refuseResponse(403, '{"error":{"code":"FORBIDDEN","message":"No console role."}}')
      );
    vi.stubGlobal('fetch', fetchMock);

    const capture = collectHandlers();
    const unsubscribe = subscribeToTrafficStream(capture.handlers);
    await flushMicrotasks();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(capture.errors).toContain('No console role.');
    expect(capture.statuses).toContain('disconnected');

    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    unsubscribe();
  });

  it('aborts the reader and cancels retries when unsubscribed', async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn().mockResolvedValueOnce(streamResponse([': keepalive\n\n']));
    vi.stubGlobal('fetch', fetchMock);

    const capture = collectHandlers();
    const unsubscribe = subscribeToTrafficStream(capture.handlers);
    await flushMicrotasks();

    unsubscribe();
    expect(capture.statuses[capture.statuses.length - 1]).toBe('disconnected');

    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
