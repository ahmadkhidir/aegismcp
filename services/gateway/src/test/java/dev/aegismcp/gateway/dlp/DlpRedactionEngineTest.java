package dev.aegismcp.gateway.dlp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Overlap resolution tests for the redaction engine.
 * Anchors: FEAT-005, C-001.
 */
class DlpRedactionEngineTest {

    private final DlpRedactionEngine engine = new DlpRedactionEngine();

    private static DlpDetection credential(int start, int end) {
        return new DlpDetection(DlpCategory.API_KEY, DlpPatternType.AWS_ACCESS_KEY, start, end,
                "AKIAIOSFODNN7EXAMPLE", "[REDACTED_SECRET:AWS_KEY]");
    }

    private static DlpDetection entropy(int start, int end) {
        return new DlpDetection(DlpCategory.HIGH_ENTROPY_SECRET, DlpPatternType.HIGH_ENTROPY_TOKEN,
                start, end, "aws=AKIAIOSFODNN7EXAMPLE", "[REDACTED_SECRET:HIGH_ENTROPY]");
    }

    @Test
    @DisplayName("C-001: a credential pattern outranks an entropy span that starts earlier and overlaps")
    void credentialOutranksEarlierEntropySpan() {
        List<DlpDetection> resolved = engine.resolveNonOverlapping(List.of(entropy(0, 24), credential(4, 24)));

        assertEquals(1, resolved.size());
        assertEquals(DlpPatternType.AWS_ACCESS_KEY, resolved.get(0).patternType());
        assertEquals(4, resolved.get(0).start());
        assertEquals(24, resolved.get(0).end());
    }

    @Test
    @DisplayName("FEAT-005: an entropy span no specific pattern claims is still masked")
    void entropySpanWithoutCompetingPatternIsKept() {
        List<DlpDetection> resolved = engine.resolveNonOverlapping(List.of(entropy(0, 24)));

        assertEquals(1, resolved.size());
        assertEquals(DlpPatternType.HIGH_ENTROPY_TOKEN, resolved.get(0).patternType());
    }

    @Test
    @DisplayName("FEAT-005: a credential and an adjacent entropy span are both masked")
    void adjacentSpansAreBothKept() {
        List<DlpDetection> resolved = engine.resolveNonOverlapping(List.of(entropy(4, 10), credential(0, 4)));

        assertEquals(2, resolved.size());
        assertEquals(0, resolved.get(0).start());
        assertEquals(4, resolved.get(1).start());
    }

    @Test
    @DisplayName("FEAT-005: the longer of two spans with the same start wins")
    void longerSpanWinsOnEqualStart() {
        List<DlpDetection> resolved = engine.resolveNonOverlapping(
                List.of(credential(0, 6), credential(0, 10)));

        assertEquals(1, resolved.size());
        assertEquals(10, resolved.get(0).end());
    }

    @Test
    @DisplayName("FEAT-005: an overlapping entropy span is dropped rather than merged")
    void overlappingEntropySpansDoNotDuplicate() {
        List<DlpDetection> resolved = engine.resolveNonOverlapping(List.of(entropy(0, 10), entropy(5, 15)));

        assertEquals(1, resolved.size());
        assertEquals(0, resolved.get(0).start());
        assertEquals(10, resolved.get(0).end());
    }
}
