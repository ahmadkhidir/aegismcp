package dev.aegismcp.gateway.approval;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies bounded retries, delivery records, and failure isolation for out-of-band approval
 * notifications: a broken destination is retried, recorded without its payload, and never denies
 * the suspended call by itself.
 *
 * <p>Anchors: FEAT-006, NFR-023.
 */
class ApprovalNotificationDispatcherTest {

    private static ApprovalNotification notification(String ticketId) {
        return new ApprovalNotification(ticketId, "agent-1", "drop_database",
                "{\"secret\":\"[REDACTED]\"}", "pol_db", null,
                "2026-11-23T10:00:00Z", "2026-11-23T10:05:00Z", 90.0);
    }

    /** A channel whose first {@code failures} attempts fail, then succeeds. */
    private static final class FlakyChannel implements ApprovalNotificationChannel {
        private final String name;
        private final int failures;
        private final AtomicInteger attempts = new AtomicInteger();

        private FlakyChannel(String name, int failures) {
            this.name = name;
            this.failures = failures;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public void deliver(ApprovalNotification notification) throws Exception {
            if (attempts.incrementAndGet() <= failures) {
                throw new java.io.IOException(
                        "connection refused by https://hooks.example/" + TestCredentials.hex(12));
            }
        }
    }

    @Test
    @DisplayName("FEAT-006: a failing destination is retried and its recovery is recorded")
    void retriesUntilDelivered() throws Exception {
        FlakyChannel flaky = new FlakyChannel("slack", 2);
        ApprovalNotificationDispatcher dispatcher = new ApprovalNotificationDispatcher(
                List.of(flaky), 3, Duration.ofMillis(1), Runnable::run, false, duration -> {
                });

        ApprovalNotificationDispatcher.DeliveryReport report =
                dispatcher.dispatch(notification("appr_1")).get();

        assertEquals(1, report.deliveries().size());
        assertTrue(report.anyDelivered());
        assertEquals(3, report.deliveries().get(0).attempts());
        assertEquals(3, flaky.attempts.get());
        assertTrue(dispatcher.recordFor("appr_1", "slack").orElseThrow().delivered());
    }

    @Test
    @DisplayName("FEAT-006: an exhausted destination is recorded without its URL or payload")
    void failureIsRecordedWithoutSecretDetail() throws Exception {
        ApprovalNotificationDispatcher dispatcher = new ApprovalNotificationDispatcher(
                List.of(new FlakyChannel("webhook", Integer.MAX_VALUE)), 2, Duration.ZERO,
                Runnable::run, false, duration -> {
                });

        ApprovalNotificationDispatcher.DeliveryReport report =
                dispatcher.dispatch(notification("appr_2")).get();

        assertTrue(report.allFailed());
        ApprovalNotificationDispatcher.DeliveryRecord record =
                dispatcher.recordFor("appr_2", "webhook").orElseThrow();
        assertFalse(record.delivered());
        assertEquals(2, record.attempts());
        assertFalse(record.failureReason().contains("hooks.example"),
                "A webhook URL is a credential and must not appear in a delivery record");
    }

    @Test
    @DisplayName("FEAT-006: one destination failing does not suppress the other")
    void channelsAreIndependent() throws Exception {
        List<String> deliveredTo = new ArrayList<>();
        ApprovalNotificationChannel healthy = new ApprovalNotificationChannel() {
            @Override
            public String name() {
                return "email";
            }

            @Override
            public void deliver(ApprovalNotification notification) {
                deliveredTo.add(notification.ticketId());
            }
        };

        ApprovalNotificationDispatcher dispatcher = new ApprovalNotificationDispatcher(
                List.of(new FlakyChannel("slack", Integer.MAX_VALUE), healthy), 1, Duration.ZERO,
                Runnable::run, false, duration -> {
                });

        ApprovalNotificationDispatcher.DeliveryReport report =
                dispatcher.dispatch(notification("appr_3")).get();

        assertTrue(report.anyDelivered());
        assertFalse(report.allFailed());
        assertEquals(List.of("appr_3"), deliveredTo);
        assertFalse(dispatcher.recordFor("appr_3", "slack").orElseThrow().delivered());
        assertTrue(dispatcher.recordFor("appr_3", "email").orElseThrow().delivered());
    }

    @Test
    @DisplayName("FEAT-006: no configured destination completes without contacting anything")
    void noChannelIsANoOp() throws Exception {
        ApprovalNotificationDispatcher dispatcher = ApprovalNotificationDispatcher.none();

        ApprovalNotificationDispatcher.DeliveryReport report =
                dispatcher.dispatch(notification("appr_4")).get();

        assertFalse(dispatcher.hasChannels());
        assertTrue(report.deliveries().isEmpty());
        assertFalse(report.anyDelivered());
        assertFalse(report.allFailed());
    }
}
