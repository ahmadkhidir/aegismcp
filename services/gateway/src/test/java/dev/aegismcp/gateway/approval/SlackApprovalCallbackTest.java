package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the Slack interactive approval callback FEAT-006 defines: signature and timestamp
 * authentication, operator mapping and role refusal, approve and reject through the console path,
 * and replay safety for a ticket that is already resolved, expired, or unknown.
 *
 * <p>Anchors: FEAT-006, C-004, C-014, C-001.
 */
class SlackApprovalCallbackTest {

    private static final String SIGNING_SECRET = TestCredentials.signingSecret();
    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final String APPROVER_SLACK_ID = "U-ELENA";
    private static final String VIEWER_SLACK_ID = "U-VIEWER";
    private static final String APPROVER = "elena@example.com";

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    private ApprovalManager approvalManager;
    private SlackApprovalCallback callback;

    @BeforeEach
    void setUp() {
        approvalManager = new ApprovalManager(
                Duration.ofMinutes(5), ApprovalNotificationConfig.none());

        SlackOperatorRegistry registry = SlackOperatorRegistry.parse(
                "[{\"slackUserId\":\"" + APPROVER_SLACK_ID + "\",\"operator\":\"" + APPROVER
                        + "\",\"roles\":[\"operator\"]},"
                        + "{\"slackUserId\":\"" + VIEWER_SLACK_ID + "\",\"operator\":\"viewer@example.com\","
                        + "\"roles\":[\"viewer\"]}]",
                "AEGIS_SLACK_OPERATORS");
        ApprovalNotificationConfig.Slack slack = new ApprovalNotificationConfig.Slack(
                URI.create("https://hooks.slack.com/services/T/B/X"), SIGNING_SECRET, registry);
        callback = new SlackApprovalCallback(slack, approvalManager, mapper, clock);
    }

    @AfterEach
    void tearDown() {
        approvalManager.close();
    }

    private String openTicket() {
        approvalManager.createAndSuspendTicket(
                "agent-dba", "drop_database", mapper.createObjectNode().put("secret", "value"),
                90.0, "pol_db", Duration.ofMinutes(5));
        return approvalManager.getTickets("pending").get(0).id();
    }

    private CompletableFuture<InterceptionVerdict> pendTicket(String ticketId) {
        return approvalManager.createAndSuspendTicket(
                "agent-dba", "drop_database_" + ticketId, mapper.createObjectNode(),
                90.0, "pol_db", Duration.ofMinutes(5));
    }

    private byte[] formBody(String slackUserId, String actionId, String ticketId) throws Exception {
        ObjectNode interaction = mapper.createObjectNode();
        interaction.put("type", "block_actions");
        interaction.putObject("user").put("id", slackUserId);
        ArrayNode actions = interaction.putArray("actions");
        actions.addObject()
                .put("action_id", actionId)
                .put("value", ticketId);
        String json = mapper.writeValueAsString(interaction);
        return ("payload=" + URLEncoder.encode(json, StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8);
    }

    private String sign(String timestamp, byte[] body, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update(("v0:" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
        mac.update(body);
        return "v0=" + HexFormat.of().formatHex(mac.doFinal());
    }

    private SlackApprovalCallback.Result call(String user, String action, String ticketId)
            throws Exception {
        byte[] body = formBody(user, action, ticketId);
        String timestamp = String.valueOf(NOW.getEpochSecond());
        return callback.handle(timestamp, sign(timestamp, body, SIGNING_SECRET), body);
    }

    @Test
    @DisplayName("FEAT-006: an authenticated Approve click approves the ticket and reports the outcome")
    void approvesThroughSlack() throws Exception {
        CompletableFuture<InterceptionVerdict> suspended = pendTicket("approve-case");
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        SlackApprovalCallback.Result result = call(
                APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);

        assertEquals(200, result.status());
        assertTrue(result.body().get("replace_original").asBoolean());
        String text = result.body().get("text").asText();
        assertTrue(text.startsWith("Approved by " + APPROVER + " at "));

        ApprovalTicket ticket = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("approved", ticket.status());
        assertEquals(APPROVER, ticket.reviewedBy());
        assertNotNull(ticket.processedAt());
        assertTrue(suspended.get(1, TimeUnit.SECONDS) instanceof InterceptionVerdict.Allow);
    }

    @Test
    @DisplayName("FEAT-006 / C-001: a Reject click records SLACK_REJECTED and denies the call with -32002")
    void rejectsThroughSlack() throws Exception {
        CompletableFuture<InterceptionVerdict> suspended = pendTicket("reject-case");
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        SlackApprovalCallback.Result result = call(
                APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_REJECT, ticketId);

        assertEquals(200, result.status());
        assertTrue(result.body().get("replace_original").asBoolean());
        assertTrue(result.body().get("text").asText().startsWith("Rejected by " + APPROVER + " at "));

        ApprovalTicket ticket = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("rejected", ticket.status());
        assertEquals(SlackApprovalCallback.SLACK_REJECTION_REASON, ticket.rejectionReason());

        InterceptionVerdict verdict = suspended.get(1, TimeUnit.SECONDS);
        assertTrue(verdict instanceof InterceptionVerdict.Block);
        JsonRpcError error = ((InterceptionVerdict.Block) verdict).error();
        assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, error.code());
        assertEquals(JsonRpcError.MACHINE_APPROVAL_DENIED, error.machineCode());
    }

    @Test
    @DisplayName("FEAT-006: a callback with a wrong signature is answered 401 and changes nothing")
    void wrongSignatureChangesNothing() throws Exception {
        String ticketId = openTicket();
        byte[] body = formBody(APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);
        String timestamp = String.valueOf(NOW.getEpochSecond());

        SlackApprovalCallback.Result result = callback.handle(
                timestamp, sign(timestamp, body, TestCredentials.signingSecret()), body);

        assertEquals(401, result.status());
        assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: a callback older than 300 seconds is answered 401 and changes nothing")
    void staleTimestampChangesNothing() throws Exception {
        String ticketId = openTicket();
        byte[] body = formBody(APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);
        String staleTimestamp = String.valueOf(NOW.minusSeconds(301).getEpochSecond());

        SlackApprovalCallback.Result result = callback.handle(
                staleTimestamp, sign(staleTimestamp, body, SIGNING_SECRET), body);

        assertEquals(401, result.status());
        assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: a body that is not an approval interaction is answered 401")
    void nonApprovalPayloadIsUnauthorized() throws Exception {
        String ticketId = openTicket();
        byte[] body = "{\"type\":\"url_verification\",\"challenge\":\"abc\"}"
                .getBytes(StandardCharsets.UTF_8);
        String timestamp = String.valueOf(NOW.getEpochSecond());

        SlackApprovalCallback.Result result = callback.handle(
                timestamp, sign(timestamp, body, SIGNING_SECRET), body);

        assertEquals(401, result.status());
        assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: an unmapped Slack user is refused with an ephemeral message")
    void unmappedUserIsRefused() throws Exception {
        String ticketId = openTicket();

        SlackApprovalCallback.Result result = call(
                "U-STRANGER", SlackApprovalNotifier.ACTION_APPROVE, ticketId);

        assertEquals(200, result.status());
        assertEquals("ephemeral", result.body().get("response_type").asText());
        assertTrue(result.body().get("text").asText().contains("not mapped"));
        assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: a mapped operator without the operator or admin role is refused")
    void mappedWithoutRoleIsRefused() throws Exception {
        String ticketId = openTicket();

        SlackApprovalCallback.Result result = call(
                VIEWER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);

        assertEquals(200, result.status());
        assertEquals("ephemeral", result.body().get("response_type").asText());
        assertTrue(result.body().get("text").asText().contains("role"));
        assertEquals("pending", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: a replayed click reports the recorded decision and applies no second one")
    void replayReportsRecordedOutcome() throws Exception {
        String ticketId = openTicket();
        call(APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);

        SlackApprovalCallback.Result replay = call(
                APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_REJECT, ticketId);

        assertEquals(200, replay.status());
        assertTrue(replay.body().get("replace_original").asBoolean());
        assertTrue(replay.body().get("text").asText().contains("Already approved by " + APPROVER));

        ApprovalTicket ticket = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("approved", ticket.status(), "The replay must not overwrite the first decision");
        assertEquals(APPROVER, ticket.reviewedBy());
    }

    @Test
    @DisplayName("FEAT-006: a click for an unknown ticket is answered 200 without a decision")
    void unknownTicketIsReportedWithoutADecision() throws Exception {
        String unknownTicket = TestCredentials.ticketId();
        SlackApprovalCallback.Result result = call(
                APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, unknownTicket);

        assertEquals(200, result.status());
        assertFalse(result.body().get("replace_original").asBoolean());
        assertTrue(result.body().get("text").asText().contains("no longer exists"));
    }

    @Test
    @DisplayName("FEAT-006: a click after expiry reports the expired ticket and does not resume the call")
    void expiredTicketIsReported() throws Exception {
        approvalManager.createAndSuspendTicket("agent-dba", "slow_tool", mapper.createObjectNode(),
                90.0, "pol_db", Duration.ofMillis(50));
        String ticketId = approvalManager.getTickets("pending").get(0).id();
        Thread.sleep(120);

        SlackApprovalCallback.Result result = call(
                APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);

        assertEquals(200, result.status());
        assertTrue(result.body().get("replace_original").asBoolean());
        assertTrue(result.body().get("text").asText().contains("Expired at"));
    }

    @Test
    @DisplayName("FEAT-006: the exact received bytes are signed, so a content-type-independent body verifies")
    void formEncodingIsDecodedBeforeParsing() throws Exception {
        String ticketId = openTicket();
        byte[] body = formBody(APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, ticketId);
        String timestamp = String.valueOf(NOW.getEpochSecond());

        SlackApprovalCallback.Result result = callback.handle(
                timestamp, sign(timestamp, body, SIGNING_SECRET), body);

        assertEquals(200, result.status());
        assertEquals("approved", approvalManager.getTicket(ticketId).orElseThrow().status());
    }

    @Test
    @DisplayName("FEAT-006: missing Slack headers are answered 401")
    void missingHeadersAreUnauthorized() throws Exception {
        byte[] body = formBody(APPROVER_SLACK_ID, SlackApprovalNotifier.ACTION_APPROVE, "appr_x");

        assertEquals(401, callback.handle(null, null, body).status());
        assertEquals(401, callback.handle("1700000000", null, body).status());
    }
}
