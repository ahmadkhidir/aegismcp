package dev.aegismcp.gateway.anomaly;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * High-performance thread-safe sliding-window sequence tracker maintaining state per agent session.
 * Automatically evicts events outside the time window, prunes old events beyond maximum window size,
 * resets history on idle timeout, and bounds memory via LRU eviction.
 * Anchors: FEAT-004, NFR-003.
 */
public class SessionSequenceTracker {

    public static final int DEFAULT_MAX_WINDOW_EVENTS = 10;
    public static final Duration DEFAULT_WINDOW_DURATION = Duration.ofSeconds(60);
    public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofSeconds(60);
    public static final int DEFAULT_MAX_ACTIVE_SESSIONS = 50_000;

    private final int maxWindowEvents;
    private final Duration windowDuration;
    private final Duration idleTimeout;
    private final int maxActiveSessions;

    private final ConcurrentHashMap<String, AgentSessionWindow> sessions;

    public SessionSequenceTracker() {
        this(DEFAULT_MAX_WINDOW_EVENTS, DEFAULT_WINDOW_DURATION, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_ACTIVE_SESSIONS);
    }

    public SessionSequenceTracker(int maxWindowEvents, Duration windowDuration, Duration idleTimeout) {
        this(maxWindowEvents, windowDuration, idleTimeout, DEFAULT_MAX_ACTIVE_SESSIONS);
    }

    public SessionSequenceTracker(int maxWindowEvents, Duration windowDuration, Duration idleTimeout, int maxActiveSessions) {
        if (maxWindowEvents <= 0) {
            throw new IllegalArgumentException("maxWindowEvents must be positive, got: " + maxWindowEvents);
        }
        if (maxActiveSessions <= 0) {
            throw new IllegalArgumentException("maxActiveSessions must be positive, got: " + maxActiveSessions);
        }
        this.maxWindowEvents = maxWindowEvents;
        this.windowDuration = Objects.requireNonNull(windowDuration, "windowDuration must not be null");
        this.idleTimeout = Objects.requireNonNull(idleTimeout, "idleTimeout must not be null");
        this.maxActiveSessions = maxActiveSessions;
        this.sessions = new ConcurrentHashMap<>();
    }

    /**
     * Retrieves recent tool invocations for the specified agent within the active sliding window.
     * If the session has been idle longer than idleTimeout, session history is cleanly reset.
     */
    public List<ToolInvocation> getRecentInvocations(String agentId, Instant now) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(now, "now must not be null");

        AgentSessionWindow window = sessions.get(agentId);
        if (window == null) {
            return Collections.emptyList();
        }
        return window.getHistory(now, windowDuration, idleTimeout);
    }

    public List<ToolInvocation> getRecentInvocations(String agentId) {
        return getRecentInvocations(agentId, Instant.now());
    }

    /**
     * Atomically records a tool invocation in the agent's sliding window session history.
     */
    public void recordInvocation(String agentId, ToolInvocation invocation, Instant now) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(invocation, "invocation must not be null");
        Objects.requireNonNull(now, "now must not be null");

        ensureCapacity(now);

        AgentSessionWindow window = sessions.computeIfAbsent(agentId, k -> new AgentSessionWindow());
        window.record(invocation, now, windowDuration, idleTimeout, maxWindowEvents);
    }

    public void recordInvocation(String agentId, ToolInvocation invocation) {
        recordInvocation(agentId, invocation, Instant.now());
    }

    /**
     * Resets sequence memory for an agent session.
     */
    public void clearSession(String agentId) {
        if (agentId != null) {
            sessions.remove(agentId);
        }
    }

    /**
     * Checks if an agent session is currently tracked.
     */
    public boolean hasSession(String agentId) {
        return agentId != null && sessions.containsKey(agentId);
    }

    /**
     * Returns total number of active sessions tracked in memory.
     */
    public int getActiveSessionCount() {
        return sessions.size();
    }

    /**
     * Returns current number of events in an agent's window.
     */
    public int getHistorySize(String agentId, Instant now) {
        return getRecentInvocations(agentId, now).size();
    }

    /**
     * Prunes expired sessions that have been idle beyond idleTimeout.
     */
    public void pruneExpired(Instant now) {
        sessions.entrySet().removeIf(entry -> {
            AgentSessionWindow window = entry.getValue();
            return window.isIdleExpired(now, idleTimeout);
        });
    }

    /**
     * Evicts oldest inactive sessions when capacity ceiling is reached.
     */
    private void ensureCapacity(Instant now) {
        if (sessions.size() < maxActiveSessions) {
            return;
        }

        // Phase 1: Prune idle expired sessions
        pruneExpired(now);
        if (sessions.size() < maxActiveSessions) {
            return;
        }

        // Phase 2: LRU eviction - evict oldest 10%
        int toEvict = Math.max(1, maxActiveSessions / 10);
        sessions.entrySet().stream()
                .sorted(Comparator.comparing(e -> e.getValue().getLastActivity()))
                .limit(toEvict)
                .map(Map.Entry::getKey)
                .toList()
                .forEach(sessions::remove);
    }

    public int getMaxWindowEvents() {
        return maxWindowEvents;
    }

    public Duration getWindowDuration() {
        return windowDuration;
    }

    public Duration getIdleTimeout() {
        return idleTimeout;
    }

    public int getMaxActiveSessions() {
        return maxActiveSessions;
    }

    /**
     * Internal state container for an individual agent's sliding window.
     */
    public static final class AgentSessionWindow {
        private final Deque<ToolInvocation> history = new ArrayDeque<>();
        private Instant lastActivity;

        public synchronized List<ToolInvocation> getHistory(Instant now, Duration windowDuration, Duration idleTimeout) {
            if (isIdleExpired(now, idleTimeout)) {
                history.clear();
            } else {
                pruneExpiredEvents(now, windowDuration);
            }
            return new ArrayList<>(history);
        }

        public synchronized void record(ToolInvocation invocation, Instant now, Duration windowDuration,
                                        Duration idleTimeout, int maxEvents) {
            if (isIdleExpired(now, idleTimeout)) {
                history.clear();
            } else {
                pruneExpiredEvents(now, windowDuration);
            }

            history.addLast(invocation);
            while (history.size() > maxEvents) {
                history.removeFirst();
            }
            this.lastActivity = now;
        }

        public synchronized boolean isIdleExpired(Instant now, Duration idleTimeout) {
            if (lastActivity == null) {
                return true;
            }
            return Duration.between(lastActivity, now).compareTo(idleTimeout) > 0;
        }

        public synchronized Instant getLastActivity() {
            return lastActivity;
        }

        public synchronized void clear() {
            history.clear();
            lastActivity = null;
        }

        private void pruneExpiredEvents(Instant now, Duration windowDuration) {
            Instant cutoff = now.minus(windowDuration);
            while (!history.isEmpty() && history.peekFirst().timestamp().isBefore(cutoff)) {
                history.removeFirst();
            }
        }
    }
}
