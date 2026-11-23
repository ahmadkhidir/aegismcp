package dev.aegismcp.gateway.inspector;

import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.approval.ApprovalStatus;
import dev.aegismcp.gateway.approval.ApprovalTicket;
import dev.aegismcp.gateway.killswitch.GatewayMetrics;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Watches the two pieces of fleet state the stream reports besides traffic — the approval queue and
 * the threat level — and turns each change into one {@code approval} or {@code system} event (C-002).
 *
 * <p>Both sources are owned by their own packages and expose their state rather than an event hook,
 * so the observer samples on a dedicated daemon thread and diffs: a ticket that appears is reported
 * {@code pending}, a ticket that leaves the queue is reported with the status the manager recorded
 * for it, and the pending count or the threat level changing produces one {@code system} event. It
 * also publishes the pending count into {@link GatewayMetrics}, which is what C-009 reports, so the
 * console's badge and the fleet status never disagree.
 *
 * <p>Sampling runs every 100 ms and reads concurrent maps only, never the event loop: an idle gateway
 * pays one small list read, and a change reaches a subscriber well inside the desktop update budget
 * the inspector is judged on. A failure inside one sample is logged and skipped so a transient
 * exception never stops the queue from being reported.
 *
 * <p>Anchors: FEAT-006, FEAT-008, FEAT-010, NFR-005, C-002, C-009.
 */
public final class InspectorTelemetryObserver implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(InspectorTelemetryObserver.class);

    /** Sampling period for approval and threat-level changes. */
    private static final long POLL_INTERVAL_MILLIS = 100;

    /** Contract vocabulary: the ticket's timeout state is reported as {@code expired}. */
    private static final String STATUS_EXPIRED = "expired";
    private static final String STATUS_APPROVED = "approved";
    private static final String STATUS_REJECTED = "rejected";
    private static final String STATUS_PENDING = "pending";

    private final ApprovalManager approvalManager;
    private final GatewayMetrics gatewayMetrics;
    private final KillSwitchManager killSwitchManager;
    private final InspectorEventStream eventStream;

    private ScheduledExecutorService scheduler;

    /** Tickets currently in the pending queue, with the status this observer last published. */
    private final Map<String, String> trackedTickets = new HashMap<>();

    private String lastThreatLevel;
    private int lastPendingCount;
    private boolean baselineEstablished;

    public InspectorTelemetryObserver(
            ApprovalManager approvalManager,
            GatewayMetrics gatewayMetrics,
            KillSwitchManager killSwitchManager,
            InspectorEventStream eventStream
    ) {
        this.approvalManager = Objects.requireNonNull(approvalManager, "approvalManager must not be null");
        this.gatewayMetrics = Objects.requireNonNull(gatewayMetrics, "gatewayMetrics must not be null");
        this.killSwitchManager = Objects.requireNonNull(killSwitchManager, "killSwitchManager must not be null");
        this.eventStream = Objects.requireNonNull(eventStream, "eventStream must not be null");
    }

    /**
     * Starts sampling. The first sample only establishes the baseline, so starting a quiet gateway
     * does not announce a change that did not happen.
     */
    public synchronized void start() {
        if (scheduler != null) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("aegis-inspector-telemetry-", 0).daemon(true).factory());
        scheduler.scheduleWithFixedDelay(this::sample,
                POLL_INTERVAL_MILLIS, POLL_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
    }

    /**
     * One diff of the approval queue and the fleet status. Runs on the telemetry thread only; the
     * synchronized close keeps a draining node from clearing the tracked set underneath it.
     */
    private synchronized void sample() {
        try {
            List<ApprovalTicket> pending = approvalManager.getPendingTickets(Integer.MAX_VALUE);
            Set<String> pendingIds = new HashSet<>();
            for (ApprovalTicket ticket : pending) {
                pendingIds.add(ticket.id());
                if (!trackedTickets.containsKey(ticket.id())) {
                    trackedTickets.put(ticket.id(), STATUS_PENDING);
                    eventStream.publishApproval(new ApprovalEvent(
                            ticket.id(), STATUS_PENDING, ticket.expiresAt()));
                }
            }

            for (String trackedId : List.copyOf(trackedTickets.keySet())) {
                if (pendingIds.contains(trackedId)) {
                    continue;
                }
                ApprovalTicket ticket = approvalManager.getTicket(trackedId).orElse(null);
                if (ticket == null) {
                    // The manager no longer holds the ticket (it was reset); nothing to report.
                    trackedTickets.remove(trackedId);
                    continue;
                }
                String status = terminalStatus(ticket);
                if (status == null) {
                    // Expired by the clock but not yet recorded as timed out: keep watching it.
                    continue;
                }
                trackedTickets.remove(trackedId);
                eventStream.publishApproval(new ApprovalEvent(trackedId, status, ticket.expiresAt()));
            }

            int pendingCount = pending.size();
            String threatLevel = gatewayMetrics.determineThreatLevel(killSwitchManager);
            gatewayMetrics.setPendingApprovals(pendingCount);

            if (!baselineEstablished) {
                baselineEstablished = true;
                lastThreatLevel = threatLevel;
                lastPendingCount = pendingCount;
                return;
            }

            if (!Objects.equals(threatLevel, lastThreatLevel) || pendingCount != lastPendingCount) {
                lastThreatLevel = threatLevel;
                lastPendingCount = pendingCount;
                eventStream.publishSystem(new SystemEvent(threatLevel, pendingCount));
            }
        } catch (RuntimeException e) {
            logger.warn("Live telemetry sampling failed; the approval queue will be retried", e);
        }
    }

    /** Maps a resolved ticket onto the contract's status vocabulary; {@code null} while unresolved. */
    private static String terminalStatus(ApprovalTicket ticket) {
        if (ticket == null) {
            return null;
        }
        String status = ticket.status();
        if (ApprovalStatus.APPROVED.getValue().equalsIgnoreCase(status)) {
            return STATUS_APPROVED;
        }
        if (ApprovalStatus.REJECTED.getValue().equalsIgnoreCase(status)) {
            return STATUS_REJECTED;
        }
        if (ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(status)) {
            return STATUS_EXPIRED;
        }
        return null;
    }

    @Override
    public synchronized void close() {
        ScheduledExecutorService current = scheduler;
        scheduler = null;
        baselineEstablished = false;
        trackedTickets.clear();
        if (current != null) {
            current.shutdownNow();
        }
    }
}
