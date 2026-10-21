package dev.aegismcp.cli;

import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end unit and interaction tests for {@link StdioProxy}.
 * Intercepts JSON-RPC tool calls, enforces policy, scrubs sensitive data,
 * and handles child process lifecycles.
 * Anchors: FEAT-003, FEAT-002, FEAT-005, NFR-001, NFR-002, C-001.
 */
class StdioProxyTest {

    private String javaBin;
    private String classPath;
    private PolicyEvaluator evaluator;

    @BeforeEach
    void setUp() {
        javaBin = ProcessHandle.current().info().command().orElse(System.getProperty("java.home") + "/bin/java");
        classPath = System.getProperty("java.class.path");

        String yaml = """
                id: local-test-policy
                name: Local Dev Test Policy
                version: 1.0.0
                target_agents:
                  - "*"
                default_action: DENY
                rules:
                  - id: allow-read
                    tool: read_file
                    action: ALLOW
                    constraints:
                      - argument: path
                        operator: STARTS_WITH
                        value: /tmp/
                """;

        PolicyCompiler compiler = PolicyCompiler.getInstance();
        PolicyCache cache = new PolicyCache(compiler);
        SecurityPolicy policy = SecurityPolicy.of("local-test-policy", "Local Dev Test Policy", "1.0.0", yaml, "test");
        cache.putPolicy(policy);
        cache.bindAgentToPolicy("*", policy.id());
        cache.bindAgentToPolicy("local-dev-agent", policy.id());

        evaluator = new PolicyEvaluator(cache);
    }

    @Test
    @DisplayName("FEAT-003 AC 1 & 2: Non-tool calls pass through directly to child process")
    void testNonToolCallPassesThrough() throws Exception {
        List<String> childCmd = List.of(javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer");

        String input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n";
        ByteArrayInputStream parentIn = new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), false);
        StdioProxy proxy = new StdioProxy(childCmd, evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));

        assertEquals(0, exitCode);
        String output = parentOut.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("\"protocolVersion\":\"2024-11-05\""));
    }

    @Test
    @DisplayName("FEAT-003 AC 2 / FEAT-005: Allowed tool call executes, and response is scrubbed by DLP engine")
    void testAllowedToolCallWithDlpScrubbing() throws Exception {
        List<String> childCmd = List.of(javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer");

        // read_file with path starting with /tmp/ is allowed per policy rule
        String input = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/test.txt\"}}}\n";
        ByteArrayInputStream parentIn = new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), false);
        StdioProxy proxy = new StdioProxy(childCmd, evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));

        assertEquals(0, exitCode);
        String output = parentOut.toString(StandardCharsets.UTF_8);

        // Verify DLP engine scrubbed the secret key from MockMcpChildServer
        assertFalse(output.contains("AKIAIOSFODNN7EXAMPLE"), "AWS secret access key must be scrubbed by DLP");
        assertTrue(output.contains("[REDACTED_API_KEY]"), "Scrubbed output should contain redaction token");

        // Verify inspector rendered log
        String errOutput = parentErr.toString(StandardCharsets.UTF_8);
        assertTrue(errOutput.contains("TOOL: read_file"));
        assertTrue(errOutput.contains("VERDICT: [ALLOWED]"));
    }

    @Test
    @DisplayName("FEAT-003 AC 2 / C-001: Unauthorized tool call is BLOCKED and error synthesized without reaching child")
    void testBlockedToolCallSynthesizesError() throws Exception {
        List<String> childCmd = List.of(javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer");

        // bash:exec is not allowed by policy
        String input = "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/call\",\"params\":{\"name\":\"bash:exec\",\"arguments\":{\"cmd\":\"whoami\"}}}\n";
        ByteArrayInputStream parentIn = new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), false);
        StdioProxy proxy = new StdioProxy(childCmd, evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));

        assertEquals(0, exitCode);
        String output = parentOut.toString(StandardCharsets.UTF_8);

        // Valid JSON-RPC error response returned with -32001 Policy Violation
        assertTrue(output.contains("\"id\":42"));
        assertTrue(output.contains("\"code\":-32001"));
        assertTrue(output.contains("Policy Violation"));

        // Inspector log should record BLOCKED verdict
        String errOutput = parentErr.toString(StandardCharsets.UTF_8);
        assertTrue(errOutput.contains("TOOL: bash:exec"));
        assertTrue(errOutput.contains("VERDICT: [BLOCKED]"));
    }

    @Test
    @DisplayName("FEAT-003: Propagates child process non-zero exit code cleanly")
    void testChildExitCodePropagation() throws Exception {
        List<String> childCmd = List.of(javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer", "exit-immediately", "7");

        ByteArrayInputStream parentIn = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), false);
        StdioProxy proxy = new StdioProxy(childCmd, evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));

        assertEquals(7, exitCode, "Proxy must propagate child exit code");
    }

    @Test
    @DisplayName("FEAT-003: Empty command returns exit code 1")
    void testEmptyCommandFails() throws Exception {
        ByteArrayInputStream parentIn = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), false);
        StdioProxy proxy = new StdioProxy(List.of(), evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));

        assertEquals(1, exitCode);
        assertTrue(parentErr.toString(StandardCharsets.UTF_8).contains("No target MCP server command provided"));
    }
}
