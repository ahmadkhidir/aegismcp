package dev.aegismcp.gateway.dlp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Deterministic redaction engine that resolves overlapping detections and performs
 * high-throughput span substitution.
 * Anchors: FEAT-005, NFR-002.
 */
public final class DlpRedactionEngine {

    /**
     * Merges and de-duplicates overlapping detections, giving priority to specific regex patterns
     * over general entropy detections, and longer spans over shorter spans.
     */
    public List<DlpDetection> resolveNonOverlapping(List<DlpDetection> detections) {
        if (detections == null || detections.isEmpty()) {
            return Collections.emptyList();
        }

        List<DlpDetection> sorted = new ArrayList<>(detections);
        sorted.sort((d1, d2) -> {
            int cmp = Integer.compare(d1.start(), d2.start());
            if (cmp != 0) {
                return cmp;
            }
            // If start is same, prefer regex patterns over entropy scanner
            boolean d1Entropy = d1.patternType() == DlpPatternType.HIGH_ENTROPY_TOKEN;
            boolean d2Entropy = d2.patternType() == DlpPatternType.HIGH_ENTROPY_TOKEN;
            if (d1Entropy != d2Entropy) {
                return d1Entropy ? 1 : -1;
            }
            // Prefer longer span
            return Integer.compare(d2.end(), d1.end());
        });

        List<DlpDetection> nonOverlapping = new ArrayList<>(sorted.size());
        int lastEnd = -1;

        for (DlpDetection current : sorted) {
            if (current.start() >= lastEnd) {
                nonOverlapping.add(current);
                lastEnd = current.end();
            }
        }

        return nonOverlapping;
    }

    /**
     * Applies the given non-overlapping detections to redact the input string.
     */
    public String applyRedactions(String text, List<DlpDetection> nonOverlappingDetections) {
        if (text == null || text.isEmpty() || nonOverlappingDetections.isEmpty()) {
            return text;
        }

        StringBuilder sb = new StringBuilder(text.length());
        int cursor = 0;

        for (DlpDetection detection : nonOverlappingDetections) {
            if (detection.start() > cursor) {
                sb.append(text, cursor, detection.start());
            }
            sb.append(detection.replacement());
            cursor = detection.end();
        }

        if (cursor < text.length()) {
            sb.append(text, cursor, text.length());
        }

        return sb.toString();
    }
}
