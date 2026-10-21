package dev.aegismcp.gateway.anomaly;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Circuit breaker managing agent quarantine states following behavioral anomaly detections.
 * Once tripped, subsequent tool calls from the quarantined agent are blocked immediately.
 * Anchors: FEAT-004, C-001, NFR-027.
 */
public class AnomalyCircuitBreaker {

    public record QuarantineRecord(
            String agentId,
            String reason,
            SecurityViolation violation,
            Instant trippedAt
    ) {
        public QuarantineRecord {
            Objects.requireNonNull(agentId, "agentId must not be null");
            Objects.requireNonNull(reason, "reason must not be null");
            if (trippedAt == null) {
                trippedAt = Instant.now();
            }
        }
    }

    private final Duration quarantineDuration;
    private final ConcurrentHashMap<String, QuarantineRecord> quarantinedAgents;

    /**
     * Creates a circuit breaker with indefinite quarantine (requires manual reset).
     */
    public AnomalyCircuitBreaker() {
        this(null);
    }

    /**
     * Creates a circuit breaker with a time-bounded quarantine duration.
     *
     * @param quarantineDuration duration after which quarantine automatically expires, or null for indefinite
     */
    public AnomalyCircuitBreaker(Duration quarantineDuration) {
        this.quarantineDuration = quarantineDuration;
        this.quarantinedAgents = new ConcurrentHashMap<>();
    }

    /**
     * Checks if the given agent is currently in a quarantined state.
     */
    public boolean isQuarantined(String agentId, Instant now) {
        if (agentId == null) {
            return false;
        }
        QuarantineRecord record = quarantinedAgents.get(agentId);
        if (record == null) {
            return false;
        }

        // Check time-based expiration if configured
        if (quarantineDuration != null) {
            Instant expiresAt = record.trippedAt().plus(quarantineDuration);
            if (now.isAfter(expiresAt)) {
                quarantinedAgents.remove(agentId, record);
                return false;
            }
        }

        return true;
    }

    public boolean isQuarantined(String agentId) {
        return isQuarantined(agentId, Instant.now());
    }

    /**
     * Trips the circuit breaker, placing the agent into a quarantined state.
     */
    public void trip(String agentId, String reason, SecurityViolation violation, Instant now) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        quarantinedAgents.put(agentId, new QuarantineRecord(agentId, reason, violation, now));
    }

    public void trip(String agentId, String reason, SecurityViolation violation) {
        trip(agentId, reason, violation, Instant.now());
    }

    /**
     * Resets the circuit breaker for an agent, restoring normal operational state.
     */
    public void reset(String agentId) {
        if (agentId != null) {
            quarantinedAgents.remove(agentId);
        }
    }

    /**
     * Returns quarantine details if the agent is actively quarantined.
     */
    public Optional<QuarantineRecord> getQuarantine(String agentId, Instant now) {
        if (!isQuarantined(agentId, now)) {
            return Optional.empty();
        }
        return Optional.ofNullable(quarantinedAgents.get(agentId));
    }

    public Optional<QuarantineRecord> getQuarantine(String agentId) {
        return getQuarantine(agentId, Instant.now());
    }

    public String getQuarantineReason(String agentId, Instant now) {
        return getQuarantine(agentId, now)
                .map(QuarantineRecord::reason)
                .orElse("Agent is quarantined due to policy violation");
    }

    public String getQuarantineReason(String agentId) {
        return getQuarantineReason(agentId, Instant.now());
    }

    public Duration getQuarantineDuration() {
        return quarantineDuration;
    }

    public int getQuarantinedAgentCount() {
        return quarantinedAgents.size();
    }
}
