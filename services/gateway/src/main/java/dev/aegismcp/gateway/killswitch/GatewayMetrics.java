package dev.aegismcp.gateway.killswitch;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory thread-safe metrics collector for system status, summary, and hourly timeseries
 * dashboards.
 *
 * <p>Hourly buckets cover the 24 hours ending at the current hour; a bucket is initialised when the
 * clock reaches its hour and never reports a stale count. Anchors: C-009, C-010, C-020, FEAT-010.
 */
public class GatewayMetrics {

    public static final String THREAT_NORMAL = "NORMAL";
    public static final String THREAT_ELEVATED = "ELEVATED";
    public static final String THREAT_LOCKDOWN = "LOCKDOWN";

    /** Number of hourly buckets the timeseries and the reporting window cover. */
    public static final int HOURS_IN_WINDOW = 24;

    private static final long SECONDS_PER_HOUR = 3600L;

    private final Instant startTime;
    private final AtomicInteger activeConnections;
    private final AtomicLong totalRequests24h;
    private final AtomicLong blockedViolations24h;
    private final AtomicInteger pendingApprovals;
    private final AtomicInteger activeAgents;
    private final AtomicLong toolCalls24h;
    private final AtomicInteger connectedNodes;

    private final Object bucketLock = new Object();
    private final long[] bucketHour = new long[HOURS_IN_WINDOW];
    private final long[] bucketToolCalls = new long[HOURS_IN_WINDOW];
    private final long[] bucketBlocked = new long[HOURS_IN_WINDOW];

    public GatewayMetrics() {
        this(Instant.now());
    }

    public GatewayMetrics(Instant startTime) {
        this.startTime = startTime != null ? startTime : Instant.now();
        this.activeConnections = new AtomicInteger(0);
        this.totalRequests24h = new AtomicLong(0);
        this.blockedViolations24h = new AtomicLong(0);
        this.pendingApprovals = new AtomicInteger(0);
        this.activeAgents = new AtomicInteger(0);
        this.toolCalls24h = new AtomicLong(0);
        this.connectedNodes = new AtomicInteger(1);
    }

    public void incrementActiveConnections() {
        activeConnections.incrementAndGet();
    }

    public void decrementActiveConnections() {
        activeConnections.updateAndGet(v -> Math.max(0, v - 1));
    }

    public void setActiveConnections(int count) {
        activeConnections.set(Math.max(0, count));
    }

    public void recordRequest() {
        totalRequests24h.incrementAndGet();
    }

    public void recordToolCall() {
        totalRequests24h.incrementAndGet();
        toolCalls24h.incrementAndGet();
        recordHourly(1, 0);
    }

    public void recordBlockedViolation() {
        blockedViolations24h.incrementAndGet();
        recordHourly(0, 1);
    }

    private void recordHourly(long toolCalls, long blocked) {
        long hour = currentHour();
        synchronized (bucketLock) {
            int slot = (int) Math.floorMod(hour, (long) HOURS_IN_WINDOW);
            if (bucketHour[slot] != hour) {
                bucketHour[slot] = hour;
                bucketToolCalls[slot] = 0;
                bucketBlocked[slot] = 0;
            }
            bucketToolCalls[slot] += toolCalls;
            bucketBlocked[slot] += blocked;
        }
    }

    private static long currentHour() {
        return Instant.now().getEpochSecond() / SECONDS_PER_HOUR;
    }

    public void setPendingApprovals(int count) {
        pendingApprovals.set(Math.max(0, count));
    }

    public void incrementPendingApprovals() {
        pendingApprovals.incrementAndGet();
    }

    public void decrementPendingApprovals() {
        pendingApprovals.updateAndGet(v -> Math.max(0, v - 1));
    }

    public void setActiveAgents(int count) {
        activeAgents.set(Math.max(0, count));
    }

    public void setConnectedNodes(int count) {
        connectedNodes.set(Math.max(0, count));
    }

    public int getActiveConnections() {
        return activeConnections.get();
    }

    public int getConnectedNodes() {
        return connectedNodes.get();
    }

    public long getTotalRequests24h() {
        return totalRequests24h.get();
    }

    public long getBlockedViolations24h() {
        return blockedViolations24h.get();
    }

    public int getPendingApprovals() {
        return pendingApprovals.get();
    }

    public int getActiveAgents() {
        return activeAgents.get();
    }

    public long getToolCalls24h() {
        return toolCalls24h.get();
    }

    public long getUptimeSeconds() {
        return Math.max(0, Duration.between(startTime, Instant.now()).toSeconds());
    }

    /**
     * Computes the current system threat level given the kill-switch state.
     */
    public String determineThreatLevel(KillSwitchManager killSwitchManager) {
        if (killSwitchManager != null && killSwitchManager.isGlobalLockdown()) {
            return THREAT_LOCKDOWN;
        }
        if (killSwitchManager != null && killSwitchManager.hasActiveQuarantines()) {
            return THREAT_ELEVATED;
        }
        if (blockedViolations24h.get() > 50 || pendingApprovals.get() > 10) {
            return THREAT_ELEVATED;
        }
        return THREAT_NORMAL;
    }

    /**
     * Builds the C-009 SystemStatusResponse.
     */
    public KillSwitchDto.SystemStatusResponse buildSystemStatus(KillSwitchManager killSwitchManager) {
        String status = determineThreatLevel(killSwitchManager);
        return new KillSwitchDto.SystemStatusResponse(
                status,
                activeConnections.get(),
                connectedNodes.get(),
                totalRequests24h.get(),
                blockedViolations24h.get(),
                pendingApprovals.get()
        );
    }

    /**
     * Builds the C-010 MetricsSummaryResponse.
     */
    public KillSwitchDto.MetricsSummaryResponse buildMetricsSummary() {
        return new KillSwitchDto.MetricsSummaryResponse(
                activeAgents.get(),
                toolCalls24h.get(),
                blockedViolations24h.get(),
                pendingApprovals.get(),
                getUptimeSeconds()
        );
    }

    /**
     * Builds the C-020 hourly timeseries: 24 buckets ordered oldest first, ending at the current
     * hour. Hours with no traffic report zero rather than being omitted.
     */
    public KillSwitchDto.MetricsTimeseriesResponse buildTimeseries() {
        long currentHour = currentHour();
        List<KillSwitchDto.MetricsBucket> buckets = new ArrayList<>(HOURS_IN_WINDOW);
        synchronized (bucketLock) {
            for (long hour = currentHour - (HOURS_IN_WINDOW - 1); hour <= currentHour; hour++) {
                int slot = (int) Math.floorMod(hour, (long) HOURS_IN_WINDOW);
                boolean present = bucketHour[slot] == hour;
                buckets.add(new KillSwitchDto.MetricsBucket(
                        Instant.ofEpochSecond(hour * SECONDS_PER_HOUR).toString(),
                        present ? bucketToolCalls[slot] : 0L,
                        present ? bucketBlocked[slot] : 0L
                ));
            }
        }
        return new KillSwitchDto.MetricsTimeseriesResponse("HOUR", buckets);
    }
}
