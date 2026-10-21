package dev.aegismcp.gateway.anomaly;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SessionSequenceTracker sliding-window context, idle resets, and concurrency.
 * Anchors: FEAT-004, NFR-003.
 */
class SessionSequenceTrackerTest {

    @Test
    @DisplayName("FEAT-004: Records tool invocations and retrieves within sliding window")
    void testBasicRecordAndRetrieve() {
        SessionSequenceTracker tracker = new SessionSequenceTracker(5, Duration.ofSeconds(60), Duration.ofSeconds(60));
        Instant now = Instant.parse("2026-10-21T10:00:00Z");

        tracker.recordInvocation("agent-1", ToolInvocation.of("read_file", now), now);
        tracker.recordInvocation("agent-1", ToolInvocation.of("transform_data", now.plusSeconds(5)), now.plusSeconds(5));

        List<ToolInvocation> history = tracker.getRecentInvocations("agent-1", now.plusSeconds(10));
        assertEquals(2, history.size());
        assertEquals("read_file", history.get(0).toolName());
        assertEquals("transform_data", history.get(1).toolName());
    }

    @Test
    @DisplayName("FEAT-004: Prunes history when max window events count is exceeded")
    void testMaxWindowEventsPruning() {
        SessionSequenceTracker tracker = new SessionSequenceTracker(3, Duration.ofSeconds(60), Duration.ofSeconds(60));
        Instant now = Instant.parse("2026-10-21T10:00:00Z");

        tracker.recordInvocation("agent-1", ToolInvocation.of("tool-1", now), now);
        tracker.recordInvocation("agent-1", ToolInvocation.of("tool-2", now.plusSeconds(1)), now.plusSeconds(1));
        tracker.recordInvocation("agent-1", ToolInvocation.of("tool-3", now.plusSeconds(2)), now.plusSeconds(2));
        tracker.recordInvocation("agent-1", ToolInvocation.of("tool-4", now.plusSeconds(3)), now.plusSeconds(3));

        List<ToolInvocation> history = tracker.getRecentInvocations("agent-1", now.plusSeconds(4));
        assertEquals(3, history.size(), "Window should cap at maxWindowEvents=3");
        assertEquals("tool-2", history.get(0).toolName());
        assertEquals("tool-3", history.get(1).toolName());
        assertEquals("tool-4", history.get(2).toolName());
    }

    @Test
    @DisplayName("FEAT-004: Prunes events older than sliding window duration")
    void testWindowDurationExpiration() {
        SessionSequenceTracker tracker = new SessionSequenceTracker(10, Duration.ofSeconds(30), Duration.ofSeconds(120));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        tracker.recordInvocation("agent-1", ToolInvocation.of("old_tool", t0), t0);
        tracker.recordInvocation("agent-1", ToolInvocation.of("recent_tool", t0.plusSeconds(20)), t0.plusSeconds(20));

        // Evaluate at t0 + 40s: old_tool (at t0) is 40s old (> 30s window), recent_tool (at t0+20) is 20s old (<= 30s)
        List<ToolInvocation> history = tracker.getRecentInvocations("agent-1", t0.plusSeconds(40));
        assertEquals(1, history.size());
        assertEquals("recent_tool", history.get(0).toolName());
    }

    @Test
    @DisplayName("FEAT-004 AC 3: Resets session history cleanly after exceeding idle timeout")
    void testIdleTimeoutReset() {
        SessionSequenceTracker tracker = new SessionSequenceTracker(10, Duration.ofSeconds(120), Duration.ofSeconds(60));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        tracker.recordInvocation("agent-1", ToolInvocation.of("read_file", t0), t0);

        // Within idle timeout (45s elapsed < 60s idle timeout)
        List<ToolInvocation> activeHistory = tracker.getRecentInvocations("agent-1", t0.plusSeconds(45));
        assertEquals(1, activeHistory.size());

        // Beyond idle timeout (75s elapsed > 60s idle timeout)
        List<ToolInvocation> idleHistory = tracker.getRecentInvocations("agent-1", t0.plusSeconds(75));
        assertTrue(idleHistory.isEmpty(), "Idle timeout must cleanly reset session sequence history");

        // When activity resumes, fresh history begins
        Instant tResume = t0.plusSeconds(80);
        tracker.recordInvocation("agent-1", ToolInvocation.of("new_task", tResume), tResume);
        List<ToolInvocation> resumedHistory = tracker.getRecentInvocations("agent-1", tResume);
        assertEquals(1, resumedHistory.size());
        assertEquals("new_task", resumedHistory.get(0).toolName());
    }

    @Test
    @DisplayName("FEAT-004: Thread-safe concurrent tool calls update session window atomically")
    void testConcurrentToolCalls() throws InterruptedException {
        int threads = 10;
        int callsPerThread = 20;
        SessionSequenceTracker tracker = new SessionSequenceTracker(100, Duration.ofSeconds(60), Duration.ofSeconds(60));
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);
        Instant now = Instant.now();

        for (int i = 0; i < threads; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < callsPerThread; j++) {
                        tracker.recordInvocation("agent-concurrent", ToolInvocation.of("tool-" + threadId + "-" + j, now), now);
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        executor.shutdown();

        List<ToolInvocation> history = tracker.getRecentInvocations("agent-concurrent", now);
        assertEquals(100, history.size(), "Should contain exactly maxWindowEvents=100 without corruption");
    }

    @Test
    @DisplayName("NFR-003 / FEAT-004: Evicts oldest terminated session state windows on memory pressure")
    void testLruCapacityEviction() {
        SessionSequenceTracker tracker = new SessionSequenceTracker(5, Duration.ofSeconds(60), Duration.ofSeconds(60), 10);
        Instant now = Instant.parse("2026-10-21T10:00:00Z");

        // Fill capacity with 10 agents
        for (int i = 0; i < 10; i++) {
            tracker.recordInvocation("agent-" + i, ToolInvocation.of("tool", now.plusSeconds(i)), now.plusSeconds(i));
        }
        assertEquals(10, tracker.getActiveSessionCount());

        // Adding 11th agent triggers LRU eviction
        tracker.recordInvocation("agent-new", ToolInvocation.of("tool", now.plusSeconds(20)), now.plusSeconds(20));
        assertTrue(tracker.getActiveSessionCount() <= 10, "Tracker capacity must remain bounded");
        assertTrue(tracker.hasSession("agent-new"));
    }
}
