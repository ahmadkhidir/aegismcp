package dev.aegismcp.gateway.dlp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Deterministic redaction engine that resolves overlapping detections and performs
 * high-throughput span substitution.
 *
 * <p>A specific pattern outranks the entropy heuristic: when a credential pattern and a high-entropy
 * candidate overlap, the credential wins and carries its family marker, so a credential joined to a
 * label without whitespace ({@code aws=AKIAIOSFODNN7EXAMPLE}) is reported as {@code AWS_KEY} rather
 * than as an anonymous high-entropy span. The entropy scanner only fills the spans no specific
 * pattern claims.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
public final class DlpRedactionEngine {

    /** Earlier span first; on the same start, the longer span first. */
    private static final Comparator<DlpDetection> START_THEN_LONGEST =
            Comparator.comparingInt(DlpDetection::start)
                    .thenComparing(Comparator.comparingInt(DlpDetection::end).reversed());

    /**
     * Merges and de-duplicates overlapping detections, giving priority to specific regex patterns
     * over general entropy detections, and longer spans over shorter spans.
     */
    public List<DlpDetection> resolveNonOverlapping(List<DlpDetection> detections) {
        if (detections == null || detections.isEmpty()) {
            return Collections.emptyList();
        }

        List<DlpDetection> specific = new ArrayList<>(detections.size());
        List<DlpDetection> entropy = new ArrayList<>();
        for (DlpDetection detection : detections) {
            if (detection.patternType() == DlpPatternType.HIGH_ENTROPY_TOKEN) {
                entropy.add(detection);
            } else {
                specific.add(detection);
            }
        }

        specific.sort(START_THEN_LONGEST);
        List<DlpDetection> specificResolved = selectNonOverlapping(specific);
        List<DlpDetection> resolved = new ArrayList<>(specificResolved);

        entropy.sort(START_THEN_LONGEST);
        int specificIndex = 0;
        int lastEntropyEnd = -1;
        for (DlpDetection candidate : entropy) {
            while (specificIndex < specificResolved.size()
                    && specificResolved.get(specificIndex).end() <= candidate.start()) {
                specificIndex++;
            }
            boolean overlapsSpecific = specificIndex < specificResolved.size()
                    && specificResolved.get(specificIndex).start() < candidate.end();
            if (overlapsSpecific || candidate.start() < lastEntropyEnd) {
                continue;
            }
            resolved.add(candidate);
            lastEntropyEnd = candidate.end();
        }

        resolved.sort(Comparator.comparingInt(DlpDetection::start));
        return resolved;
    }

    /** Keeps the first span of each overlapping group, with the sorted order deciding the winner. */
    private static List<DlpDetection> selectNonOverlapping(List<DlpDetection> sorted) {
        List<DlpDetection> selected = new ArrayList<>(sorted.size());
        int lastEnd = -1;
        for (DlpDetection current : sorted) {
            if (current.start() >= lastEnd) {
                selected.add(current);
                lastEnd = current.end();
            }
        }
        return selected;
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
