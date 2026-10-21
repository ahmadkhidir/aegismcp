package dev.aegismcp.e2e.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.AegisGatewayServer;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import dev.aegismcp.gateway.proxy.McpProxyHandler;
import dev.aegismcp.gateway.proxy.McpProxyPipelineConfigurator;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import dev.aegismcp.gateway.validation.DynamicParameterValidator;
import dev.aegismcp.gateway.validation.DynamicValidationInterceptor;
import dev.aegismcp.gateway.validation.ToolSchema;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-End Black-Box Verification Suite for Phase 3: Dynamic Tool Parameter Validation & Policy Simulation.
 * Validates Contracts C-001, C-012 and Features FEAT-012, NFR-024.
 */
class Phase3ParameterValidationE2ETest {

    private final ObjectMapper mapper = new ObjectMapper();
    private AegisGatewayServer server;
    private DynamicParameterValidator parameterValidator;
    private DynamicValidationInterceptor validationInterceptor;
    private HttpClient httpClient;
    private String baseUrl;

    @BeforeEach
    void setUp() throws Exception {
        // 1. Boot AegisGatewayServer on dynamic ephemeral port (0)
        server = new AegisGatewayServer("127.0.0.1", 0);
        server.start();

        int boundPort = server.getPort();
        assertTrue(boundPort > 0, "Server must be successfully bound to dynamic port");
        baseUrl = "http://127.0.0.1:" + boundPort;

        // 2. Obtain shared DynamicParameterValidator from PolicyManagementHandler
        parameterValidator = server.getPolicyManagementHandler().getParameterValidator();

        // 3. Register Tool Schemas for testing
        // Schema A: Calculation tool requiring numeric parameter 'amount'
        String calcSchema = """
                {
                  "type": "object",
                  "properties": {
                    "amount": { "type": "number" },
                    "taxRate": { "type": "number" }
                  },
                  "required": ["amount"]
                }
                """;
        parameterValidator.getSchemaRegistry().registerSchema("calculate_tax", mapper.readTree(calcSchema));

        // Schema B: Filesystem tool restricted to allowed base directory /var/app/data
        String fileSchema = """
                {
                  "type": "object",
                  "properties": {
                    "path": { "type": "string" },
                    "lines": { "type": "integer" }
                  },
                  "required": ["path"]
                }
                """;
        parameterValidator.getSchemaRegistry().registerSchema("read_file", mapper.readTree(fileSchema), "/var/app/data");

        // Schema C: Database tool for SQL injection defense testing
        String dbSchema = """
                {
                  "type": "object",
                  "properties": {
                    "query": { "type": "string" }
                  },
                  "required": ["query"]
                }
                """;
        parameterValidator.getSchemaRegistry().registerTool(ToolSchema.database("query_db", mapper.readTree(dbSchema)));

        // Schema D: Command tool for Shell injection defense testing
        String cmdSchema = """
                {
                  "type": "object",
                  "properties": {
                    "command": { "type": "string" }
                  },
                  "required": ["command"]
                }
                """;
        parameterValidator.getSchemaRegistry().registerTool(ToolSchema.command("exec_cmd", mapper.readTree(cmdSchema)));

        // 4. Register Declarative Security Policy for Policy Simulation tests (C-012)
        String policyYaml = """
                id: pol-phase3-validation
                name: Phase 3 Validation Policy
                version: 1.0.0
                target_agents:
                  - "*"
                rules:
                  - id: rule-read-file
                    tool: read_file
                    action: ALLOW
                  - id: rule-deploy-prod
                    tool: deploy_prod
                    action: REQUIRE_APPROVAL
                  - id: rule-delete-db
                    tool: delete_database
                    action: DENY
                """;
        SecurityPolicy policy = new SecurityPolicy(
                "pol-phase3-validation",
                "Phase 3 Validation Policy",
                "1.0.0",
                policyYaml,
                SecurityPolicy.STATUS_ACTIVE,
                "commit-phase3-001",
                "2026-10-21T12:00:00Z"
        );
        server.getPolicyCache().putPolicy(policy);

        // 5. Configure DynamicValidationInterceptor and McpProxyHandler on incoming client connections
        AuditLedger auditLedger = server.getAuditLedger();
        validationInterceptor = new DynamicValidationInterceptor(parameterValidator, auditLedger);

        McpProxyHandler proxyHandler = new McpProxyHandler(
                McpProxyHandler.DEFAULT_RPC_PATH,
                JsonRpcCodec.getInstance(),
                validationInterceptor,
                UpstreamClient.mockEcho(),
                server.getVirtualThreadExecutor(),
                false // Allow test requests with Bearer token
        );

        server.getServerChannel().pipeline().addFirst("phase3-pipeline-injector", new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                if (msg instanceof SocketChannel ch) {
                    ch.pipeline().addLast("phase3-channel-activator", new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelActive(ChannelHandlerContext childCtx) throws Exception {
                            McpProxyPipelineConfigurator.configure(childCtx.pipeline(), proxyHandler);
                            childCtx.pipeline().remove(this);
                            super.channelActive(childCtx);
                        }
                    });
                }
                ctx.fireChannelRead(msg);
            }
        });

        // 6. Build HTTP client
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    // =========================================================================
    // 1. C-001: Invalid Parameter Types -> Code -32005 (FEAT-012, NFR-024)
    // =========================================================================

    @Test
    @DisplayName("FEAT-012 / C-001: Tool call with invalid parameter type is rejected with JSON-RPC error -32005")
    void testInvalidParameterTypeRejectedWithCode32005() throws IOException, InterruptedException {
        // Send string "one-hundred" where numeric amount is required
        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-type-err-1",
                  "method": "tools/call",
                  "params": {
                    "name": "calculate_tax",
                    "arguments": {
                      "amount": "one-hundred-dollars",
                      "taxRate": 0.08
                    }
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-token-test")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertNotNull(response.body());

        JsonNode jsonResponse = mapper.readTree(response.body());
        assertEquals("2.0", jsonResponse.get("jsonrpc").asText());
        assertEquals("req-type-err-1", jsonResponse.get("id").asText());
        assertTrue(jsonResponse.has("error"), "Response must contain error object");

        JsonNode errorNode = jsonResponse.get("error");
        assertEquals(-32005, errorNode.get("code").asInt(), "Error code must be -32005 (Schema/Parameter Violation)");
        String errorMessage = errorNode.get("message").asText();
        assertTrue(errorMessage.startsWith("Schema/Parameter Violation:"), "Error message must indicate schema violation");
        assertTrue(errorMessage.contains("type mismatch"), "Error message must detail type mismatch");
    }

    // =========================================================================
    // 2. C-001: Directory Traversal Payloads -> Rejection & path_traversal Audit Log
    // =========================================================================

    @Test
    @DisplayName("FEAT-012 / C-001: Directory traversal (/base/../../etc/passwd and %2e%2e/) rejected with -32005 and audit logged")
    void testDirectoryTraversalPayloadsRejectedAndAuditLogged() throws IOException, InterruptedException {
        // Payload 1: canonical breakout with /var/app/data/../../etc/passwd
        String traversalPayload1 = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-trav-1",
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": {
                      "path": "/var/app/data/../../etc/passwd",
                      "lines": 10
                    }
                  }
                }
                """;

        HttpRequest request1 = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-attacker-trav")
                .POST(HttpRequest.BodyPublishers.ofString(traversalPayload1))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> response1 = httpClient.send(request1, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonResp1 = mapper.readTree(response1.body());

        assertEquals(-32005, jsonResp1.get("error").get("code").asInt());
        assertTrue(jsonResp1.get("error").get("message").asText().contains("Path traversal"));

        // Payload 2: URL-encoded traversal (%2e%2e/)
        String traversalPayload2 = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-trav-2",
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": {
                      "path": "%2e%2e/etc/passwd",
                      "lines": 5
                    }
                  }
                }
                """;

        HttpRequest request2 = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-attacker-trav")
                .POST(HttpRequest.BodyPublishers.ofString(traversalPayload2))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> response2 = httpClient.send(request2, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonResp2 = mapper.readTree(response2.body());

        assertEquals(-32005, jsonResp2.get("error").get("code").asInt());
        assertTrue(jsonResp2.get("error").get("message").asText().contains("Path traversal"));

        // Verify that path_traversal SecurityViolation was recorded
        List<SecurityViolation> violations = validationInterceptor.getRecordedViolations();
        assertFalse(violations.isEmpty(), "Interceptor must record SecurityViolation instances");
        boolean hasPathTraversalType = violations.stream()
                .anyMatch(v -> SecurityViolation.TYPE_PATH_TRAVERSAL.equals(v.violationType()));
        assertTrue(hasPathTraversalType, "Recorded violations must contain type 'path_traversal'");

        // Verify audit ledger contains blocked records with path_traversal
        server.getAuditLedger().flush();
        assertTrue(server.getAuditLedger().getTotalRecordsCount() > 0, "AuditLedger must contain blocked traversal records");
    }

    // =========================================================================
    // 3. C-001: SQL Injection Payloads -> Code -32005
    // =========================================================================

    @Test
    @DisplayName("FEAT-012 / C-001: SQL injection (UNION SELECT and ' OR '1'='1) rejected with -32005")
    void testSqlInjectionPayloadsRejected() throws IOException, InterruptedException {
        // Payload A: UNION SELECT
        String unionSelectPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-sqli-union",
                  "method": "tools/call",
                  "params": {
                    "name": "query_db",
                    "arguments": {
                      "query": "SELECT id, name FROM users WHERE id = 1 UNION SELECT password, email FROM admin"
                    }
                  }
                }
                """;

        HttpRequest requestA = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-sqli-test")
                .POST(HttpRequest.BodyPublishers.ofString(unionSelectPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> responseA = httpClient.send(requestA, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonRespA = mapper.readTree(responseA.body());

        assertEquals(-32005, jsonRespA.get("error").get("code").asInt());
        assertTrue(jsonRespA.get("error").get("message").asText().contains("SQL injection"));

        // Payload B: Tautology ' OR '1'='1
        String tautologyPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-sqli-tautology",
                  "method": "tools/call",
                  "params": {
                    "name": "query_db",
                    "arguments": {
                      "query": "SELECT * FROM accounts WHERE username = 'admin' OR '1'='1'"
                    }
                  }
                }
                """;

        HttpRequest requestB = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-sqli-test")
                .POST(HttpRequest.BodyPublishers.ofString(tautologyPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> responseB = httpClient.send(requestB, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonRespB = mapper.readTree(responseB.body());

        assertEquals(-32005, jsonRespB.get("error").get("code").asInt());
        assertTrue(jsonRespB.get("error").get("message").asText().contains("SQL injection"));
    }

    // =========================================================================
    // 4. C-001: Command Injection Payloads -> Code -32005
    // =========================================================================

    @Test
    @DisplayName("FEAT-012 / C-001: Command injection (&& cat /etc/passwd and ; rm -rf) rejected with -32005")
    void testCommandInjectionPayloadsRejected() throws IOException, InterruptedException {
        // Payload A: && cat /etc/passwd
        String cmdChainingPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-cmd-chain",
                  "method": "tools/call",
                  "params": {
                    "name": "exec_cmd",
                    "arguments": {
                      "command": "ls -l && cat /etc/passwd"
                    }
                  }
                }
                """;

        HttpRequest requestA = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-cmdi-test")
                .POST(HttpRequest.BodyPublishers.ofString(cmdChainingPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> responseA = httpClient.send(requestA, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonRespA = mapper.readTree(responseA.body());

        assertEquals(-32005, jsonRespA.get("error").get("code").asInt());
        assertTrue(jsonRespA.get("error").get("message").asText().contains("Command injection"));

        // Payload B: ; rm -rf
        String cmdSemicolonPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-cmd-semicolon",
                  "method": "tools/call",
                  "params": {
                    "name": "exec_cmd",
                    "arguments": {
                      "command": "uptime; rm -rf /"
                    }
                  }
                }
                """;

        HttpRequest requestB = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-cmdi-test")
                .POST(HttpRequest.BodyPublishers.ofString(cmdSemicolonPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> responseB = httpClient.send(requestB, HttpResponse.BodyHandlers.ofString());
        JsonNode jsonRespB = mapper.readTree(responseB.body());

        assertEquals(-32005, jsonRespB.get("error").get("code").asInt());
        assertTrue(jsonRespB.get("error").get("message").asText().contains("Command injection"));
    }

    // =========================================================================
    // 5. C-001: Valid Tool Call -> Passes to Upstream Successfully
    // =========================================================================

    @Test
    @DisplayName("FEAT-012: Valid tool call conforms to schema and executes through proxy")
    void testValidToolCallAllowed() throws IOException, InterruptedException {
        String validPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-valid-1",
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": {
                      "path": "/var/app/data/application.properties",
                      "lines": 50
                    }
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-legitimate")
                .POST(HttpRequest.BodyPublishers.ofString(validPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode jsonResp = mapper.readTree(response.body());
        assertEquals("2.0", jsonResp.get("jsonrpc").asText());
        assertEquals("req-valid-1", jsonResp.get("id").asText());
        assertFalse(jsonResp.has("error"), "Valid request must not return an error");
        assertTrue(jsonResp.has("result"), "Valid request must return result");
        assertEquals("executed", jsonResp.get("result").get("status").asText());
    }

    // =========================================================================
    // 6. C-012: POST /api/v1/policies/simulate Verdicts (ALLOWED, BLOCKED, REQUIRE_APPROVAL)
    // =========================================================================

    @Test
    @DisplayName("C-012: POST /api/v1/policies/simulate returns correct verdicts: ALLOWED, REQUIRE_APPROVAL, BLOCKED")
    void testPolicySimulationReturnsExpectedVerdicts() throws IOException, InterruptedException {
        // Case 1: ALLOWED - read_file with valid parameters matches rule-read-file action ALLOW
        String simAllowPayload = """
                {
                  "agentId": "agent-analyst",
                  "toolName": "read_file",
                  "arguments": {
                    "path": "/var/app/data/report.csv",
                    "lines": 100
                  }
                }
                """;

        HttpRequest allowReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/policies/simulate"))
                .header("Authorization", "Bearer admin-simulation-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(simAllowPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> allowResp = httpClient.send(allowReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, allowResp.statusCode());

        JsonNode allowNode = mapper.readTree(allowResp.body());
        assertEquals("ALLOWED", allowNode.get("verdict").asText());
        assertEquals("rule-read-file", allowNode.get("ruleMatched").asText());
        assertTrue(allowNode.get("violations").isEmpty());

        // Case 2: REQUIRE_APPROVAL - deploy_prod matches rule-deploy-prod action REQUIRE_APPROVAL
        String simApprovalPayload = """
                {
                  "agentId": "agent-deployer",
                  "toolName": "deploy_prod",
                  "arguments": {
                    "version": "v2.5.0",
                    "region": "us-east-1"
                  }
                }
                """;

        HttpRequest approvalReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/policies/simulate"))
                .header("Authorization", "Bearer admin-simulation-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(simApprovalPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> approvalResp = httpClient.send(approvalReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, approvalResp.statusCode());

        JsonNode approvalNode = mapper.readTree(approvalResp.body());
        assertEquals("REQUIRE_APPROVAL", approvalNode.get("verdict").asText());
        assertEquals("rule-deploy-prod", approvalNode.get("ruleMatched").asText());

        // Case 3: BLOCKED by Declarative Policy - delete_database matches rule-delete-db action DENY
        String simPolicyBlockPayload = """
                {
                  "agentId": "agent-rogue",
                  "toolName": "delete_database",
                  "arguments": {
                    "database": "prod_users"
                  }
                }
                """;

        HttpRequest polBlockReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/policies/simulate"))
                .header("Authorization", "Bearer admin-simulation-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(simPolicyBlockPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> polBlockResp = httpClient.send(polBlockReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, polBlockResp.statusCode());

        JsonNode polBlockNode = mapper.readTree(polBlockResp.body());
        assertEquals("BLOCKED", polBlockNode.get("verdict").asText());
        assertEquals("rule-delete-db", polBlockNode.get("ruleMatched").asText());
        assertFalse(polBlockNode.get("violations").isEmpty());

        // Case 4: BLOCKED by Parameter Validation - read_file with path traversal payload
        String simParamBlockPayload = """
                {
                  "agentId": "agent-analyst",
                  "toolName": "read_file",
                  "arguments": {
                    "path": "/var/app/data/../../etc/shadow",
                    "lines": 10
                  }
                }
                """;

        HttpRequest paramBlockReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/policies/simulate"))
                .header("Authorization", "Bearer admin-simulation-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(simParamBlockPayload))
                .timeout(Duration.ofSeconds(3))
                .build();

        HttpResponse<String> paramBlockResp = httpClient.send(paramBlockReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, paramBlockResp.statusCode());

        JsonNode paramBlockNode = mapper.readTree(paramBlockResp.body());
        assertEquals("BLOCKED", paramBlockNode.get("verdict").asText());
        assertEquals("parameter_validation", paramBlockNode.get("ruleMatched").asText());
        assertFalse(paramBlockNode.get("violations").isEmpty(), "Violations list must contain error details");
        assertTrue(paramBlockNode.get("violations").get(0).asText().contains("Path traversal"));
    }
}
