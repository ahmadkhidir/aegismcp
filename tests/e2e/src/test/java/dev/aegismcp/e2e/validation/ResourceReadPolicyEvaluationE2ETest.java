package dev.aegismcp.e2e.validation;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-001 makes {@code resources/read} policy-bearing alongside {@code tools/call}. This suite drives
 * the packaged gateway over HTTPS and proves the resource read takes the same identity, validation,
 * policy, anomaly, and audit path: absent from the policy it is refused, allowed it is forwarded as a
 * resource read, its {@code uri} is constrained like a tool argument, and a suspended call resumes or
 * fails on the reviewer's decision.
 *
 * <p>Anchors: FEAT-001, FEAT-002, FEAT-012, C-001, NFR-027.
 */
class ResourceReadPolicyEvaluationE2ETest extends ArtifactTest {

    private static final String AGENT = "agent-resources";
    private static final String RESOURCE_URI = "file:///workspace/reports/q3.txt";

    private static final String RESOURCE_POLICY = """
            id: pol_resources_e2e
            name: Resource Read Policy
            version: 1.0.0
            targetAgents:
              - "*"
            rules:
              - id: rule_resource_read
                tool: resources/read
                action: allow
                constraints:
                  - argument: uri
                    operator: starts_with
                    value: "file:///workspace"
            """;

    private static final String APPROVAL_POLICY = """
            id: pol_resources_approval_e2e
            name: Resource Read Approval Policy
            version: 1.0.0
            targetAgents:
              - "*"
            rules:
              - id: rule_resource_read_approval
                tool: resources/read
                action: require_approval
            """;

    private static String resourcesRead(Object id, String uri) {
        String renderedId = id instanceof String ? "\"" + id + "\"" : String.valueOf(id);
        return "{\"jsonrpc\":\"2.0\",\"id\":" + renderedId + ",\"method\":\"resources/read\","
                + "\"params\":{\"uri\":\"" + uri + "\"}}";
    }

    /**
     * Posts a resource read without waiting for its answer, so the test can act on the approval
     * ticket the gateway exposes while the call is suspended.
     */
    private CompletableFuture<HttpResponse<String>> postSuspended(GatewayHarness harness, Object id) {
        return harness.sendAsync(harness.request("/mcp/v1/rpc", harness.agentToken(AGENT))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(resourcesRead(id, RESOURCE_URI)))
                .build());
    }

    private String awaitTicket(GatewayHarness harness) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            HttpResponse<String> pending = harness.get("/api/v1/approvals/pending", harness.operatorToken());
            if (pending.statusCode() == 200) {
                for (JsonNode ticket : GatewayHarness.json(pending).path("tickets")) {
                    if (AGENT.equals(ticket.path("agentId").asText())) {
                        return ticket.path("id").asText();
                    }
                }
            }
            Thread.sleep(100);
        }
        return null;
    }

    @Test
    @DisplayName("C-001 / FEAT-002: a resources/read absent from the policy is refused and carries no result")
    void resourcesReadOutsideThePolicyIsRefused() throws Exception {
        HttpResponse<String> response = gateway().postJson("/mcp/v1/rpc",
                gateway().agentToken(AGENT), resourcesRead("res-blocked", RESOURCE_URI));

        JsonNode body = ContractAssertions.assertRpcError(response, 403, -32001, "TOOL_NOT_PERMITTED");
        assertEquals("res-blocked", body.path("id").asText(), "the request id is repeated unchanged");
        assertTrue(body.path("result").isMissingNode(), "a refused resource read carries no result");
        ContractAssertions.assertNoInternalDetail(response);
    }

    @Test
    @DisplayName("C-001 / FEAT-002: an allowed resources/read is forwarded as a resource read")
    void allowedResourcesReadIsForwarded() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().policyYaml(RESOURCE_POLICY))) {
            HttpResponse<String> response = harness.postJson("/mcp/v1/rpc",
                    harness.agentToken(AGENT), resourcesRead("res-allowed", RESOURCE_URI));

            ContractAssertions.assertStatus(200, response);
            JsonNode body = GatewayHarness.json(response);
            assertEquals("res-allowed", body.path("id").asText());
            assertEquals("resources/read", body.path("result").path("method").asText(),
                    "the upstream receives the resource read, not the projection used to evaluate it");
        }
    }

    @Test
    @DisplayName("C-001 / FEAT-002: a resources/read outside its uri constraint is refused")
    void resourcesReadOutsideItsUriConstraintIsRefused() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().policyYaml(RESOURCE_POLICY))) {
            ContractAssertions.assertRpcError(
                    harness.postJson("/mcp/v1/rpc", harness.agentToken(AGENT),
                            resourcesRead("res-constrained", "file:///tmp/report.txt")),
                    403, -32001, "ARGUMENT_CONSTRAINT_VIOLATED");
        }
    }

    @Test
    @DisplayName("C-001 / FEAT-006: a suspended resources/read fails on rejection and resumes on approval")
    void suspendedResourcesReadFollowsTheReviewersDecision() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().policyYaml(APPROVAL_POLICY))) {
            CompletableFuture<HttpResponse<String>> rejected = postSuspended(harness, "res-rejected");
            String rejectedTicket = awaitTicket(harness);
            assertNotNull(rejectedTicket, "the resource read is suspended for approval");
            ContractAssertions.assertStatus(200, harness.postJson(
                    "/api/v1/approvals/" + rejectedTicket + "/reject", harness.operatorToken(),
                    "{\"reason\":\"Resource not authorised for this agent\"}"));
            JsonNode denial = ContractAssertions.assertRpcError(
                    rejected.get(10, TimeUnit.SECONDS), 403, -32002, "APPROVAL_DENIED");
            assertEquals("res-rejected", denial.path("id").asText());

            CompletableFuture<HttpResponse<String>> approved = postSuspended(harness, "res-approved");
            String approvedTicket = awaitTicket(harness);
            assertNotNull(approvedTicket, "the second resource read is suspended for approval");
            ContractAssertions.assertStatus(200, harness.postJson(
                    "/api/v1/approvals/" + approvedTicket + "/approve", harness.operatorToken(), ""));

            HttpResponse<String> resumed = approved.get(10, TimeUnit.SECONDS);
            ContractAssertions.assertStatus(200, resumed);
            assertEquals("resources/read",
                    GatewayHarness.json(resumed).path("result").path("method").asText(),
                    "an approved resource read resumes as a resource read");
        }
    }
}
