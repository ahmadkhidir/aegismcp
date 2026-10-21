package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying path traversal detection and canonical resolution.
 * Anchors: FEAT-012 AC 2, NFR-024.
 */
class PathTraversalSanitizerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private PathTraversalSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        sanitizer = new PathTraversalSanitizer();
    }

    @Test
    @DisplayName("FEAT-012 AC 2: Canonical resolution identifies out-of-bounds traversal (/allowed/dir/../../etc/shadow)")
    void testCanonicalPathResolutionOutOfBounds() {
        ToolSchema toolSchema = ToolSchema.filesystem("read_file", null, "/allowed/dir");

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/allowed/dir/../../etc/shadow");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertFalse(violations.isEmpty(), "Out-of-bounds traversal must be detected");
        ValidationViolation v = violations.get(0);
        assertEquals(SecurityViolation.TYPE_PATH_TRAVERSAL, v.violationType());
        assertTrue(v.message().contains("Path traversal detected"));
    }

    @Test
    @DisplayName("FEAT-012 AC 2: Relative parent traversal (../../etc/passwd) is detected and blocked")
    void testRelativeParentTraversal() {
        ToolSchema toolSchema = ToolSchema.filesystem("filesystem_read", null, "/workspace");

        ObjectNode args = mapper.createObjectNode();
        args.put("filepath", "../../etc/passwd");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertFalse(violations.isEmpty());
        assertEquals("filepath", violations.get(0).parameterName());
        assertEquals(SecurityViolation.TYPE_PATH_TRAVERSAL, violations.get(0).violationType());
    }

    @Test
    @DisplayName("FEAT-012 AC 2: Windows style path traversal (..\\..\\windows) is detected")
    void testWindowsPathTraversal() {
        ToolSchema toolSchema = ToolSchema.filesystem("file_tool", null, "/app");

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "..\\..\\windows\\system32");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertFalse(violations.isEmpty());
        assertEquals(SecurityViolation.TYPE_PATH_TRAVERSAL, violations.get(0).violationType());
    }

    @Test
    @DisplayName("FEAT-012: URL encoded directory traversal (%2e%2e%2f) is detected")
    void testUrlEncodedPathTraversal() {
        ToolSchema toolSchema = ToolSchema.of("generic_tool", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "%2e%2e%2fetc%2fshadow");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertFalse(violations.isEmpty());
        assertEquals(SecurityViolation.TYPE_PATH_TRAVERSAL, violations.get(0).violationType());
    }

    @Test
    @DisplayName("FEAT-012: Null byte path injection (file.txt\\0.png) is detected")
    void testNullBytePathInjection() {
        ToolSchema toolSchema = ToolSchema.filesystem("read", null, "/sandbox");

        ObjectNode args = mapper.createObjectNode();
        args.put("filename", "secret.txt\0.png");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("Null byte"));
    }

    @Test
    @DisplayName("FEAT-012: Safe path inside allowed base directory passes cleanly")
    void testSafePathPasses() {
        ToolSchema toolSchema = ToolSchema.filesystem("read_file", null, "/allowed/dir");

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/allowed/dir/subfolder/data.json");

        List<ValidationViolation> violations = sanitizer.sanitize(toolSchema, args);
        assertTrue(violations.isEmpty(), "Path inside allowed directory should pass without violations");
    }
}
