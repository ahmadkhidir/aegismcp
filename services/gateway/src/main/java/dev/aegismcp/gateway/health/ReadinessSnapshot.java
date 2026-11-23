package dev.aegismcp.gateway.health;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.Map;

/**
 * Immutable readiness report served by {@code GET /ready}.
 *
 * <p>The {@code reason} member is present only when the node must not receive agent traffic, and the
 * {@code checks} members always name exactly the configuration, policy, and audit-ledger
 * dependencies (C-023, FEAT-001).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"status", "reason", "checks", "timestamp"})
public record ReadinessSnapshot(
        String status,
        String reason,
        Map<String, Check> checks,
        String timestamp
) {

    /**
     * Status of one dependency check.
     */
    @JsonPropertyOrder({"status"})
    public record Check(String status) {
    }
}
