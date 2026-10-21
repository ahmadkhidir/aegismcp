package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying DynamicValidationInterceptor Netty pipeline integration,
 * fail-closed rejection with JSON-RPC error -32005, and AuditLedger recording.
 * Anchors: FEAT-012, C-001, NFR-024, schema.md#SecurityViolation.
 */
class DynamicValidationInterceptorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private DynamicParameterValidator validator;
    private AuditLedger auditLedger;
    private DynamicValidationInterceptor interceptor;

    @BeforeEach
    void setUp() throws Exception {
        validator = new DynamicParameterValidator();
        auditLedger = new AuditLedger();
        interceptor = new DynamicValidationInterceptor(validator, auditLedger);

        // Register tools in validator
        String fsSchema = """
                {
                  "type": "object",
                  "properties": {
                    "path": { "type": "string" },
                    "lines": { "type": "integer" }
                  },
                  "required": ["path"]
                }
                """;
        validator.getSchemaRegistry().registerSchema("read_file", mapper.readTree(fsSchema), "/safe/root");

        String cmdSchema = """
                {
                  "type": "object",
                  "properties": {
                    "command": { "type": "string" }
                  },
                  "required": ["command"]
                }
                """;
        validator.getSchemaRegistry().registerTool(ToolSchema.command("exec_cmd", mapper.readTree(cmdSchema)));
    }

    @AfterEach
    void tearDown() {
        if (auditLedger != null) {
            auditLedger.close();
        }
    }

    @Test
    @DisplayName("FEAT-001: Non-tool calls pass directly through interceptor")
    void testNonToolCallPassesThrough() {
        SecurityContext context = SecurityContext.of(AgentIdentity.fromBearer("test-token"), new InetSocketAddress(8080));
        JsonRpcRequest pingRequest = new JsonRpcRequest(JsonRpcId.of(1), "ping", null);

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, pingRequest);
        InterceptionVerdict verdict = future.join();

        assertTrue(verdict instanceof InterceptionVerdict.Allow);
    }

    @Test
    @DisplayName("FEAT-012 AC 5: Schema violation rejects tool call with JSON-RPC error -32005 Schema/Parameter Violation")
    void testSchemaViolationRejectedWithErrorCode32005() {
        SecurityContext context = SecurityContext.of(AgentIdentity.fromBearer("agent-test-token"), new InetSocketAddress(8080));

        ObjectNode toolParams = mapper.createObjectNode();
        toolParams.put("name", "read_file");
        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("path", "file.txt");
        arguments.put("lines", "twenty"); // string instead of integer
        toolParams.set("arguments", arguments);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-1"), "tools/call", toolParams);

        InterceptionVerdict verdict = interceptor.intercept(context, request).join();
        assertTrue(verdict instanceof InterceptionVerdict.Block);

        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(-32005, block.error().code());
        assertTrue(block.error().message().startsWith("Schema/Parameter Violation:"));
        assertTrue(block.error().message().contains("type mismatch"));
    }

    @Test
    @DisplayName("FEAT-012 AC 5 & AC 6: Path traversal records SecurityViolation of type path_traversal and returns -32005")
    void testPathTraversalRecordedAndBlocked() {
        SecurityContext context = SecurityContext.of(AgentIdentity.fromBearer("agent-attacker"), new InetSocketAddress(8080));

        ObjectNode toolParams = mapper.createObjectNode();
        toolParams.put("name", "read_file");
        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("path", "/safe/root/../../etc/shadow");
        toolParams.set("arguments", arguments);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-2"), "tools/call", toolParams);

        InterceptionVerdict verdict = interceptor.intercept(context, request).join();
        assertTrue(verdict instanceof InterceptionVerdict.Block);

        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(-32005, block.error().code());
        assertTrue(block.error().message().contains("Path traversal"));

        // Verify recorded SecurityViolation
        List<SecurityViolation> violations = interceptor.getRecordedViolations();
        assertEquals(1, violations.size());
        SecurityViolation recorded = violations.get(0);
        assertEquals(SecurityViolation.TYPE_PATH_TRAVERSAL, recorded.violationType());
        assertEquals("high", recorded.severity());

        // Verify flushed to AuditLedger
        auditLedger.flush();
        assertTrue(auditLedger.getTotalRecordsCount() > 0, "Audit ledger should contain recorded violation record");
    }

    @Test
    @DisplayName("FEAT-012 AC 5 & AC 6: Command injection records SecurityViolation of type schema_violation and returns -32005")
    void testCommandInjectionRecordedAndBlocked() {
        SecurityContext context = SecurityContext.of(AgentIdentity.fromBearer("agent-shell-inject"), new InetSocketAddress(8080));

        ObjectNode toolParams = mapper.createObjectNode();
        toolParams.put("name", "exec_cmd");
        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("command", "ls -l && rm -rf /");
        toolParams.set("arguments", arguments);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-3"), "tools/call", toolParams);

        InterceptionVerdict verdict = interceptor.intercept(context, request).join();
        assertTrue(verdict instanceof InterceptionVerdict.Block);

        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(-32005, block.error().code());
        assertTrue(block.error().message().contains("Command injection"));

        List<SecurityViolation> violations = interceptor.getRecordedViolations();
        assertEquals(1, violations.size());
        assertEquals(SecurityViolation.TYPE_SCHEMA_VIOLATION, violations.get(0).violationType());
    }

    @Test
    @DisplayName("FEAT-012: Valid tool call passes with InterceptionVerdict.Allow")
    void testValidToolCallAllowed() {
        SecurityContext context = SecurityContext.of(AgentIdentity.fromBearer("agent-normal"), new InetSocketAddress(8080));

        ObjectNode toolParams = mapper.createObjectNode();
        toolParams.put("name", "read_file");
        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("path", "/safe/root/documents/readme.txt");
        arguments.put("lines", 100);
        toolParams.set("arguments", arguments);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-4"), "tools/call", toolParams);

        InterceptionVerdict verdict = interceptor.intercept(context, request).join();
        assertTrue(verdict instanceof InterceptionVerdict.Allow);
        assertTrue(interceptor.getRecordedViolations().isEmpty());
    }
}
