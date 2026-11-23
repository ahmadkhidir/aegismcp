package dev.aegismcp.gateway.inspector;

/**
 * One row of the redaction summary a {@code traffic} event carries: how many spans of one DLP
 * pattern were masked before the event was broadcast.
 *
 * <p>{@code category} is the contract's coarse label ({@code SECRET} or {@code PII}) and {@code type}
 * is the specific detected pattern, so an operator can tell an API key from a credit card without the
 * event ever carrying the matched value.
 *
 * <p>Anchors: FEAT-005, FEAT-008, C-002.
 */
public record RedactionSummary(String category, String type, int count) {
}
