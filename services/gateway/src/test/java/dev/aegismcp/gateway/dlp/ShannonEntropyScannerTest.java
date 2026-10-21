package dev.aegismcp.gateway.dlp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the Shannon entropy computation and high-entropy secret scanner.
 * Anchors: FEAT-005, NFR-002.
 */
class ShannonEntropyScannerTest {

    private static String runtimeConcat(String... parts) {
        return String.join("", parts);
    }

    @Test
    @DisplayName("FEAT-005: Repeated single character has zero entropy")
    void testZeroEntropy() {
        assertEquals(0.0, ShannonEntropyScanner.calculateEntropy("AAAAAAAAAA"), 0.0001);
    }

    @Test
    @DisplayName("FEAT-005: Random base64 string has high entropy (> 4.5 bits/char)")
    void testHighEntropyBase64() {
        String randomBase64 = runtimeConcat("4K8vL1x+", "Q3mZ9rP0", "wT7yU6iO", "5nB3vC2x");
        double entropy = ShannonEntropyScanner.calculateEntropy(randomBase64);
        assertTrue(entropy >= 4.5, "Expected entropy >= 4.5, got: " + entropy);
    }

    @Test
    @DisplayName("FEAT-005: English prose and common words have low entropy (< 4.0 bits/char)")
    void testLowEntropyEnglish() {
        String englishText = "standardoperatingprocedure";
        double entropy = ShannonEntropyScanner.calculateEntropy(englishText);
        assertTrue(entropy < 4.0, "Expected entropy < 4.0, got: " + entropy);
    }

    @Test
    @DisplayName("FEAT-005: ShannonEntropyScanner flags random secret tokens")
    void testScanHighEntropyToken() {
        DlpConfig config = DlpConfig.defaultConfig();
        ShannonEntropyScanner scanner = new ShannonEntropyScanner(config);

        String token = runtimeConcat("4K8vL1x+", "Q3mZ9rP0", "wT7yU6iO", "5nB3vC2x");
        String input = "The token is " + token + " for authentication";
        List<DlpDetection> detections = scanner.scan(input);

        assertFalse(detections.isEmpty());
        DlpDetection detection = detections.getFirst();
        assertEquals(DlpCategory.HIGH_ENTROPY_SECRET, detection.category());
        assertEquals(token, detection.matchedText());
    }

    @Test
    @DisplayName("FEAT-005: ShannonEntropyScanner excludes UUIDs from false positives")
    void testExcludeUuid() {
        DlpConfig config = DlpConfig.defaultConfig();
        ShannonEntropyScanner scanner = new ShannonEntropyScanner(config);

        String input = "Session id: 550e8400-e29b-41d4-a716-446655440000 active now";
        List<DlpDetection> detections = scanner.scan(input);

        assertTrue(detections.isEmpty(), "UUID must not be flagged as high entropy secret");
    }

    @Test
    @DisplayName("FEAT-005: ShannonEntropyScanner excludes PascalCase/camelCase identifiers")
    void testExcludeCodeIdentifiers() {
        DlpConfig config = DlpConfig.defaultConfig();
        ShannonEntropyScanner scanner = new ShannonEntropyScanner(config);

        String input = "Invoke AbstractAnnotationConfigDispatcherServletInitializer.handle()";
        List<DlpDetection> detections = scanner.scan(input);

        assertTrue(detections.isEmpty(), "Code identifiers should not be flagged as secrets");
    }
}
