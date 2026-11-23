package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * Payload of a {@code traffic} event (C-002): one intercepted {@code tools/call}.
 *
 * <p>{@code arguments} holds the intercepted request arguments after DLP redaction, and
 * {@code redactions} reports what was masked, so the live inspector can render payloads and
 * redaction pills without the stream ever carrying a secret or personal data.
 *
 * <p>The stream prepends the monotonic {@code eventId}, which is why this record starts at
 * {@code timestamp}.
 *
 * <p>Anchors: FEAT-008, NFR-005, C-002.
 */
public record TrafficEvent(
        String timestamp,
        String agentId,
        String toolName,
        JsonNode arguments,
        String decision,
        double latencyMs,
        List<String> matchedRuleIds,
        List<RedactionSummary> redactions
) {
}
