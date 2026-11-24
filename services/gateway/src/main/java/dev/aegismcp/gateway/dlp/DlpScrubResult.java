package dev.aegismcp.gateway.dlp;

import java.util.List;
import java.util.Objects;

/**
 * Outcome of one scrub: the sanitized payload together with the detections that produced it.
 *
 * <p>{@link #redactionCount()} is the number of spans the scrubber actually replaced. Reporting it
 * with the payload lets the audit trail seal it as {@code redactionCount} (C-013) and the inspector
 * summarize it (C-002) without scanning the payload a second time to learn what was masked.
 *
 * <p>Offsets in {@code detections} are relative to the scanned unit: the whole string for a text
 * scrub, the whole payload for a byte scrub, and the individual text node for a tree scrub.
 *
 * <p>Anchors: FEAT-005, C-001, C-002, C-013.
 *
 * @param payload    the sanitized payload; identical to the input when nothing was detected
 * @param detections the non-overlapping detections that were replaced, in payload order
 */
public record DlpScrubResult<T>(T payload, List<DlpDetection> detections) {

    public DlpScrubResult {
        Objects.requireNonNull(detections, "detections must not be null");
        detections = List.copyOf(detections);
    }

    /** A scrub that found nothing: the payload is returned untouched and the count is zero. */
    public static <T> DlpScrubResult<T> unchanged(T payload) {
        return new DlpScrubResult<>(payload, List.of());
    }

    /** The number of spans this scrub replaced. */
    public int redactionCount() {
        return detections.size();
    }

    /** True when at least one span was replaced. */
    public boolean redacted() {
        return !detections.isEmpty();
    }
}
