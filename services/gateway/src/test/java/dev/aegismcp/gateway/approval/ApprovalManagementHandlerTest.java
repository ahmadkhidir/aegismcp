package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying the approval management contracts C-003, C-004, C-014, and C-019 against the
 * Netty handler. Authentication is delegated to a test double that models the verified-token
 * outcome; role enforcement itself is owned by the composition root's verified authorizers.
 *
 * <p>Anchors: FEAT-006, FEAT-008, C-003, C-004, C-014, C-019.
 */
class ApprovalManagementHandlerTest {

    private static final String OPERATOR_TOKEN = "Bearer operator-token";
    private static final String FORBIDDEN_TOKEN = "Bearer viewer-token";
    private static final String REVIEWER_SUBJECT = "operator@example.com";
    private static final String SLACK_SIGNING_SECRET = TestCredentials.signingSecret();
    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private ApprovalManager approvalManager;
    private ApprovalManagementHandler handler;
    private EmbeddedChannel channel;
    private ApprovalManagementHandler.ApprovalAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        approvalManager = new ApprovalManager(
                Duration.ofMinutes(5), ApprovalNotificationConfig.none());

        authorizer = (path, method, bearerToken) -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return ApprovalManagementHandler.ApprovalAuthorizer.AuthResult
                        .unauthenticated("Missing authentication credentials");
            }
            if (bearerToken.contains("viewer") || bearerToken.contains("readonly")) {
                return ApprovalManagementHandler.ApprovalAuthorizer.AuthResult
                        .forbidden("Insufficient permissions for this operation");
            }
            return ApprovalManagementHandler.ApprovalAuthorizer.AuthResult.verified(REVIEWER_SUBJECT);
        };

        handler = new ApprovalManagementHandler(approvalManager, mapper, authorizer);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.close();
        }
        if (approvalManager != null) {
            approvalManager.close();
        }
    }

    private FullHttpResponse send(HttpMethod method, String uri, String payload, String authHeader) {
        ByteBuf content = payload != null
                ? Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8))
                : Unpooled.EMPTY_BUFFER;
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, method, uri, content);
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }
        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode body(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    private String createTicket(String toolName) {
        approvalManager.createAndSuspendTicket(
                "agent-7", toolName, mapper.createObjectNode().put("secret", "value"),
                80.0, "pol_critical", Duration.ofMinutes(5));
        return approvalManager.getTickets("pending").stream()
                .filter(ticket -> ticket.toolName().equals(toolName))
                .findFirst()
                .orElseThrow()
                .id();
    }

    @Test
    @DisplayName("C-003: GET /api/v1/approvals/pending without a token returns 401")
    void pendingWithoutTokenReturns401() {
        FullHttpResponse response = send(HttpMethod.GET, ApprovalManagementHandler.PENDING_PATH, null, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-003: a verified principal without the contract role returns 403")
    void pendingWithForbiddenRoleReturns403() {
        FullHttpResponse response = send(HttpMethod.GET, ApprovalManagementHandler.PENDING_PATH, null,
                FORBIDDEN_TOKEN);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-003: pending tickets are ordered by expiry ascending")
    void pendingTicketsAreOrderedByExpiry() throws Exception {
        approvalManager.createAndSuspendTicket("agent-a", "tool_slow", mapper.createObjectNode(),
                50.0, "pol", Duration.ofMinutes(4));
        approvalManager.createAndSuspendTicket("agent-b", "tool_fast", mapper.createObjectNode(),
                50.0, "pol", Duration.ofMinutes(1));

        FullHttpResponse response = send(HttpMethod.GET, ApprovalManagementHandler.PENDING_PATH, null,
                OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = body(response);
        assertTrue(json.has("tickets"));
        JsonNode tickets = json.get("tickets");
        assertEquals(2, tickets.size());
        assertTrue(tickets.get(0).get("expiresAt").asText()
                .compareTo(tickets.get(1).get("expiresAt").asText()) < 0);
        assertEquals("pending", tickets.get(0).get("status").asText());
        assertTrue(tickets.get(0).has("argumentsPayload"));
        assertFalse(tickets.get(0).get("argumentsPayload").asText().contains("secret"));
        response.release();
    }

    @Test
    @DisplayName("C-003: an out-of-range limit is answered 400")
    void pendingLimitOutOfRangeReturns400() {
        FullHttpResponse response = send(HttpMethod.GET,
                ApprovalManagementHandler.PENDING_PATH + "?limit=101", null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-004: approve resolves the ticket with the verified reviewer subject")
    void approveUsesVerifiedSubject() throws Exception {
        String ticketId = createTicket("wire_transfer");

        FullHttpResponse response = send(HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/approve", null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = body(response);
        assertEquals(ticketId, json.get("ticketId").asText());
        assertEquals("approved", json.get("status").asText());
        assertEquals(REVIEWER_SUBJECT, json.get("reviewedBy").asText());
        assertNotNull(json.get("processedAt").asText());
        response.release();
    }

    @Test
    @DisplayName("C-004: approve on an unknown ticket returns 404 and on a resolved ticket 409")
    void approveUnknownAndResolvedTickets() {
        FullHttpResponse unknown = send(HttpMethod.POST, "/api/v1/approvals/appr_missing/approve", null,
                OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.NOT_FOUND, unknown.status());
        unknown.release();

        String ticketId = createTicket("delete_all_data");
        FullHttpResponse first = send(HttpMethod.POST, "/api/v1/approvals/" + ticketId + "/approve", null,
                OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.OK, first.status());
        first.release();

        FullHttpResponse second = send(HttpMethod.POST, "/api/v1/approvals/" + ticketId + "/approve", null,
                OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.CONFLICT, second.status());
        second.release();
    }

    @Test
    @DisplayName("C-014: reject without a reason returns 400 and with one records the reason")
    void rejectRequiresReason() throws Exception {
        String ticketId = createTicket("execute_sql");

        FullHttpResponse empty = send(HttpMethod.POST, "/api/v1/approvals/" + ticketId + "/reject",
                "{\"reason\":\"   \"}", OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.BAD_REQUEST, empty.status());
        empty.release();

        FullHttpResponse rejected = send(HttpMethod.POST, "/api/v1/approvals/" + ticketId + "/reject",
                "{\"reason\":\"Prohibited on production\"}", OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.OK, rejected.status());

        JsonNode json = body(rejected);
        assertEquals("rejected", json.get("status").asText());
        assertEquals(REVIEWER_SUBJECT, json.get("reviewedBy").asText());
        assertEquals("Prohibited on production", json.get("rejectionReason").asText());
        rejected.release();
    }

    @Test
    @DisplayName("C-019: history requires a status and reports the matching total")
    void historyRequiresStatusAndCounts() throws Exception {
        FullHttpResponse missing = send(HttpMethod.GET, ApprovalManagementHandler.APPROVALS_BASE_PATH,
                null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.BAD_REQUEST, missing.status());
        missing.release();

        String approvedId = createTicket("tool_ok");
        approvalManager.approve(approvedId, REVIEWER_SUBJECT);
        String rejectedId = createTicket("tool_denied");
        approvalManager.reject(rejectedId, REVIEWER_SUBJECT, "not permitted");

        FullHttpResponse response = send(HttpMethod.GET,
                ApprovalManagementHandler.APPROVALS_BASE_PATH + "?status=rejected&limit=5&offset=0",
                null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = body(response);
        assertEquals(1, json.get("total").asInt());
        JsonNode ticket = json.get("tickets").get(0);
        assertEquals("rejected", ticket.get("status").asText());
        assertEquals(REVIEWER_SUBJECT, ticket.get("reviewedBy").asText());
        assertEquals("not permitted", ticket.get("rejectionReason").asText());
        response.release();
    }

    @Test
    @DisplayName("C-019: an undeclared status value is answered 400")
    void historyRejectsUnknownStatus() {
        FullHttpResponse response = send(HttpMethod.GET,
                ApprovalManagementHandler.APPROVALS_BASE_PATH + "?status=pending", null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-004: an expired ticket decision is answered 410 Gone")
    void expiredTicketReturns410() throws Exception {
        approvalManager.createAndSuspendTicket("agent-exp", "tool_exp", mapper.createObjectNode(),
                50.0, "pol", Duration.ofMillis(50));
        String ticketId = approvalManager.getTickets("pending").get(0).id();
        Thread.sleep(150);

        FullHttpResponse response = send(HttpMethod.POST,
                "/api/v1/approvals/" + ticketId + "/approve", null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.GONE, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-003: a non-GET pending request is answered 405")
    void pendingWrongMethodReturns405() {
        FullHttpResponse response = send(HttpMethod.POST, ApprovalManagementHandler.PENDING_PATH, "{}",
                OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-019: an unknown sub-path under approvals is answered 404")
    void unknownSubPathReturns404() {
        FullHttpResponse response = send(HttpMethod.GET, "/api/v1/approvals/unknown", null, OPERATOR_TOKEN);
        assertEquals(HttpResponseStatus.NOT_FOUND, response.status());
        response.release();
    }

    @Test
    @DisplayName("The handler passes a non-approval path down the pipeline")
    void nonApprovalPathIsForwarded() {
        FullHttpResponse response = send(HttpMethod.GET, "/api/v1/policies", null, OPERATOR_TOKEN);
        assertNull(response);
    }

    @Test
    @DisplayName("FEAT-006: the Slack callback path answers 404 when no workspace is configured")
    void slackPathAnswers404WithoutWorkspace() {
        FullHttpResponse response = sendSlack(channel, new byte[0], "1700000000", "v0=deadbeef");
        assertEquals(HttpResponseStatus.NOT_FOUND, response.status());
        response.release();
    }

    @Test
    @DisplayName("FEAT-006: an unsigned Slack callback is answered 401 and leaves the ticket pending")
    void slackPathRejectsUnsignedCallback() throws Exception {
        String ticketId = createTicket("deploy_prod");
        byte[] body = slackForm("U-ELENA", SlackApprovalNotifier.ACTION_APPROVE, ticketId);
        EmbeddedChannel slackChannel = slackConfiguredChannel();

        try {
            FullHttpResponse response = sendSlack(slackChannel, body,
                    String.valueOf(NOW.getEpochSecond()), "v0=deadbeef");
            assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
            response.release();
            assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
        } finally {
            slackChannel.close();
        }
    }

    @Test
    @DisplayName("FEAT-006: a signed Slack Approve click approves the ticket through the endpoint")
    void slackPathApprovesTicket() throws Exception {
        String ticketId = createTicket("deploy_prod");
        byte[] body = slackForm("U-ELENA", SlackApprovalNotifier.ACTION_APPROVE, ticketId);
        String timestamp = String.valueOf(NOW.getEpochSecond());
        EmbeddedChannel slackChannel = slackConfiguredChannel();

        try {
            FullHttpResponse response = sendSlack(slackChannel, body, timestamp,
                    slackSignature(timestamp, body));
            assertEquals(HttpResponseStatus.OK, response.status());

            JsonNode json = body(response);
            assertTrue(json.get("replace_original").asBoolean());
            assertTrue(json.get("text").asText().contains("elena@example.com"));
            response.release();

            ApprovalTicket ticket = approvalManager.getTicket(ticketId).orElseThrow();
            assertEquals("approved", ticket.status());
            assertEquals("elena@example.com", ticket.reviewedBy());
        } finally {
            slackChannel.close();
        }
    }

    private EmbeddedChannel slackConfiguredChannel() {
        SlackOperatorRegistry registry = SlackOperatorRegistry.parse(
                "[{\"slackUserId\":\"U-ELENA\",\"operator\":\"elena@example.com\",\"roles\":[\"admin\"]}]",
                "AEGIS_SLACK_OPERATORS");
        ApprovalNotificationConfig.Slack slack = new ApprovalNotificationConfig.Slack(
                URI.create("https://hooks.slack.com/services/T/B/X"), SLACK_SIGNING_SECRET, registry);
        SlackApprovalCallback callback = new SlackApprovalCallback(
                slack, approvalManager, mapper, Clock.fixed(NOW, ZoneOffset.UTC));
        return new EmbeddedChannel(
                new ApprovalManagementHandler(approvalManager, mapper, authorizer, callback));
    }

    private byte[] slackForm(String slackUserId, String actionId, String ticketId) throws Exception {
        ObjectNode interaction = mapper.createObjectNode();
        interaction.put("type", "block_actions");
        interaction.putObject("user").put("id", slackUserId);
        interaction.putArray("actions").addObject()
                .put("action_id", actionId)
                .put("value", ticketId);
        String json = mapper.writeValueAsString(interaction);
        return ("payload=" + URLEncoder.encode(json, StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8);
    }

    private static String slackSignature(String timestamp, byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(
                SLACK_SIGNING_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update(("v0:" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
        mac.update(body);
        return "v0=" + HexFormat.of().formatHex(mac.doFinal());
    }

    private FullHttpResponse sendSlack(
            EmbeddedChannel target,
            byte[] body,
            String timestamp,
            String signature
    ) {
        ByteBuf content = Unpooled.wrappedBuffer(body);
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.POST,
                ApprovalManagementHandler.SLACK_INTERACTIONS_PATH, content);
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (timestamp != null) {
            request.headers().set(ApprovalManagementHandler.SLACK_TIMESTAMP_HEADER, timestamp);
        }
        if (signature != null) {
            request.headers().set(ApprovalManagementHandler.SLACK_SIGNATURE_HEADER, signature);
        }
        target.writeInbound(request);
        return target.readOutbound();
    }
}
