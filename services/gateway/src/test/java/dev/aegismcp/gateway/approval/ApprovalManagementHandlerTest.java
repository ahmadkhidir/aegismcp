package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Netty HTTP handler implementing contracts C-003 and C-004.
 * Anchors: C-003, C-004, FEAT-006.
 */
class ApprovalManagementHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private ApprovalManager approvalManager;
    private ApprovalManagementHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        approvalManager = new ApprovalManager(Duration.ofMinutes(5));
        handler = new ApprovalManagementHandler(approvalManager);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (approvalManager != null) {
            approvalManager.close();
        }
        if (channel != null) {
            channel.close();
        }
    }

    private FullHttpResponse sendRequest(HttpMethod method, String uri, String payload, String authHeader) {
        ByteBuf content = (payload != null)
                ? Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8))
                : Unpooled.EMPTY_BUFFER;

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                method,
                uri,
                content
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }

        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode parseBody(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    @Test
    @DisplayName("C-003: GET /api/v1/approvals without Bearer token returns 401 Unauthorized")
    void testGetApprovalsUnauthorized() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/approvals", null, null);

        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
    }

    @Test
    @DisplayName("C-003: GET /api/v1/approvals with Bearer token returns 200 OK and tickets array")
    void testGetApprovalsSuccess() throws Exception {
        ObjectNode args = mapper.createObjectNode();
        args.put("table", "audit_log");
        approvalManager.createAndSuspendTicket("agent-sec", "truncate_table", args, 90.0, "pol_audit", Duration.ofMinutes(5));

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/approvals", null, "Bearer operator-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertTrue(body.has("tickets"));
        JsonNode tickets = body.get("tickets");
        assertTrue(tickets.isArray());
        assertEquals(1, tickets.size());

        JsonNode t = tickets.get(0);
        assertEquals("agent-sec", t.get("agentId").asText());
        assertEquals("truncate_table", t.get("toolName").asText());
        assertEquals("pending", t.get("status").asText());
        assertEquals(90.0, t.get("riskScore").asDouble());
        assertTrue(t.has("requestedAt"));
        assertTrue(t.has("expiresAt"));
        assertTrue(t.has("arguments"));
    }

    @Test
    @DisplayName("C-003: GET /api/v1/approvals?status=pending filters tickets accurately")
    void testGetApprovalsWithStatusFilter() throws Exception {
        approvalManager.createAndSuspendTicket("agent-1", "tool_a", mapper.createObjectNode(), 50.0, "pol", Duration.ofMinutes(5));
        approvalManager.createAndSuspendTicket("agent-2", "tool_b", mapper.createObjectNode(), 60.0, "pol", Duration.ofMinutes(5));

        String ticket1Id = approvalManager.getTickets("pending").get(0).id();
        approvalManager.submitDecision(ticket1Id, "APPROVE", "admin", "ok");

        FullHttpResponse pendingResp = sendRequest(HttpMethod.GET, "/api/v1/approvals?status=pending", null, "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, pendingResp.status());
        JsonNode pendingBody = parseBody(pendingResp);
        assertEquals(1, pendingBody.get("tickets").size());
        assertEquals("pending", pendingBody.get("tickets").get(0).get("status").asText());

        FullHttpResponse approvedResp = sendRequest(HttpMethod.GET, "/api/v1/approvals?status=approved", null, "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, approvedResp.status());
        JsonNode approvedBody = parseBody(approvedResp);
        assertEquals(1, approvedBody.get("tickets").size());
        assertEquals("approved", approvedBody.get("tickets").get(0).get("status").asText());
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision without Bearer token returns 401 Unauthorized")
    void testPostDecisionUnauthorized() throws Exception {
        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/appr_123/decision",
                "{\"decision\":\"APPROVE\",\"reviewer\":\"test\",\"reason\":\"ok\"}",
                null
        );

        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision with readonly/viewer token returns 403 Forbidden")
    void testPostDecisionForbidden() throws Exception {
        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/appr_123/decision",
                "{\"decision\":\"APPROVE\",\"reviewer\":\"test\",\"reason\":\"ok\"}",
                "Bearer viewer-token-999"
        );

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision with APPROVE returns 200 OK and updates ticket")
    void testPostDecisionApproveSuccess() throws Exception {
        approvalManager.createAndSuspendTicket("agent-ops", "restart_db", mapper.createObjectNode(), 70.0, "pol", Duration.ofMinutes(5));
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        String payload = """
                {
                  "decision": "APPROVE",
                  "reviewer": "elena_rostova",
                  "reason": "Authorized scheduled maintenance"
                }
                """;

        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                payload,
                "Bearer operator-token"
        );

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertEquals(ticketId, body.get("ticketId").asText());
        assertEquals("APPROVE", body.get("status").asText());
        assertTrue(body.has("processedAt"));

        ApprovalTicket updated = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("approved", updated.status());
        assertEquals("elena_rostova", updated.reviewer());
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision with REJECT returns 200 OK and updates ticket")
    void testPostDecisionRejectSuccess() throws Exception {
        approvalManager.createAndSuspendTicket("agent-ops", "delete_backup", mapper.createObjectNode(), 95.0, "pol", Duration.ofMinutes(5));
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        String payload = """
                {
                  "decision": "REJECT",
                  "reviewer": "secops_lead",
                  "reason": "Backups cannot be deleted manually"
                }
                """;

        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                payload,
                "Bearer operator-token"
        );

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertEquals(ticketId, body.get("ticketId").asText());
        assertEquals("REJECT", body.get("status").asText());

        ApprovalTicket updated = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("rejected", updated.status());
        assertEquals("secops_lead", updated.reviewer());
        assertEquals("Backups cannot be deleted manually", updated.decisionReason());
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision with non-existent ID returns 404 Not Found")
    void testPostDecisionNotFound() throws Exception {
        String payload = "{\"decision\":\"APPROVE\",\"reviewer\":\"admin\",\"reason\":\"ok\"}";
        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/non_existent_id/decision",
                payload,
                "Bearer admin-token"
        );

        assertNotNull(response);
        assertEquals(HttpResponseStatus.NOT_FOUND, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision on already resolved ticket returns 400 Bad Request")
    void testPostDecisionAlreadyResolvedReturns400() throws Exception {
        approvalManager.createAndSuspendTicket("agent-ops", "flush_cache", mapper.createObjectNode(), 40.0, "pol", Duration.ofMinutes(5));
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        String payload = "{\"decision\":\"APPROVE\",\"reviewer\":\"admin\",\"reason\":\"first approval\"}";
        FullHttpResponse firstResp = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                payload,
                "Bearer admin-token"
        );
        assertEquals(HttpResponseStatus.OK, firstResp.status());

        // Second attempt
        FullHttpResponse secondResp = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                payload,
                "Bearer admin-token"
        );
        assertEquals(HttpResponseStatus.BAD_REQUEST, secondResp.status());
        JsonNode body = parseBody(secondResp);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("already been resolved"));
    }

    @Test
    @DisplayName("C-004: POST /api/v1/approvals/{id}/decision with invalid decision payload returns 400 Bad Request")
    void testPostDecisionInvalidDecisionPayload() throws Exception {
        approvalManager.createAndSuspendTicket("agent-ops", "action", mapper.createObjectNode(), 40.0, "pol", Duration.ofMinutes(5));
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        // Unknown decision value
        String payload = "{\"decision\":\"MAYBE\",\"reviewer\":\"admin\",\"reason\":\"not sure\"}";
        FullHttpResponse response = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                payload,
                "Bearer admin-token"
        );
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());

        // Empty body
        FullHttpResponse emptyResp = sendRequest(
                HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/decision",
                "",
                "Bearer admin-token"
        );
        assertEquals(HttpResponseStatus.BAD_REQUEST, emptyResp.status());
    }

    @Test
    @DisplayName("FEAT-006: Non-approval endpoints pass through to downstream handlers in pipeline")
    void testNonApprovalPathPassThrough() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health"
        );
        channel.writeInbound(request);

        // Request passes through to channel inbound buffer
        DefaultFullHttpRequest forwarded = channel.readInbound();
        assertNotNull(forwarded);
        assertEquals("/health", forwarded.uri());
        forwarded.release();
    }
}
