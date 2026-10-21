package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying command injection detection and token filtering.
 * Anchors: FEAT-012, NFR-024.
 */
class CommandInjectionDetectorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private CommandInjectionDetector detector;
    private ToolSchema commandTool;

    @BeforeEach
    void setUp() {
        detector = new CommandInjectionDetector();
        commandTool = ToolSchema.command("run_terminal", null);
    }

    @Test
    @DisplayName("FEAT-012: Chaining token '&&' is detected and blocked")
    void testAndChainingDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("cmd", "echo hello && cat /etc/passwd");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("&&"));
    }

    @Test
    @DisplayName("FEAT-012: Pipe token '|' is detected and blocked")
    void testPipeTokenDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("command", "cat access.log | grep -i admin");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("|"));
    }

    @Test
    @DisplayName("FEAT-012: Semicolon separator ';' is detected and blocked")
    void testSemicolonSeparatorDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("script", "ls -la; rm -rf /tmp/data");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains(";"));
    }

    @Test
    @DisplayName("FEAT-012: Backticks command substitution is detected and blocked")
    void testBackticksDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("command", "echo `whoami`");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("`"));
    }

    @Test
    @DisplayName("FEAT-012: Subshell syntax '$()' is detected and blocked")
    void testDollarSubshellDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("cmd", "echo $(cat /var/run/secrets)");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("$("));
    }

    @Test
    @DisplayName("FEAT-012: Clean single command without chaining tokens passes")
    void testCleanCommandPasses() {
        ObjectNode args = mapper.createObjectNode();
        args.put("cmd", "git status --porcelain");

        List<ValidationViolation> violations = detector.detect(commandTool, args);
        assertTrue(violations.isEmpty(), "Clean command arguments should pass without violation");
    }
}
