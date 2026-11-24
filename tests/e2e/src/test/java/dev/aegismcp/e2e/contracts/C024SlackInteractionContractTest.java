package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayOptions;
import dev.aegismcp.e2e.fixtures.SlackFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-024: POST /api/v1/integrations/slack/interactions. Anchors: C-024, FEAT-006.
 */
class C024SlackInteractionContractTest extends ArtifactTest {

    private static final String PATH = "/api/v1/integrations/slack/interactions";

    @Test
    @DisplayName("C-024: applies a signed Slack approval and refuses unauthenticated callbacks")
    void appliesSignedSlackApprovalAndRefusesUnauthenticatedCallbacks() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-slack", "deploy_prod", "{}");

        HttpResponse<String> approval = callback(harness, SlackFixtures.interaction(
                SlackFixtures.OPERATOR_MEMBER, "aegis_approve", pending.ticketId()));
        ContractAssertions.assertStatus(200, approval);
        JsonNode approved = GatewayHarness.json(approval);
        assertTrue(approved.path("replace_original").asBoolean());
        assertTrue(approved.path("text").asText().startsWith(
                        "Approved by " + SlackFixtures.MAPPED_OPERATOR + " at "),
                () -> "Unexpected Slack approval text: " + approved.path("text").asText());
        assertTrue(approved.path("text").asText().endsWith("Z"));
        assertTrue(approved.path("response_type").isMissingNode(),
                "A channel-visible decision carries no response_type");

        ContractAssertions.assertStatus(200, pending.response().get(10, TimeUnit.SECONDS));

        HttpResponse<String> replay = callback(harness, SlackFixtures.interaction(
                SlackFixtures.OPERATOR_MEMBER, "aegis_approve", pending.ticketId()));
        ContractAssertions.assertStatus(200, replay);
        JsonNode replayed = GatewayHarness.json(replay);
        assertTrue(replayed.path("replace_original").asBoolean());
        assertTrue(replayed.path("text").asText().startsWith("Already approved by "
                        + SlackFixtures.MAPPED_OPERATOR + " at "),
                () -> "Unexpected replay text: " + replayed.path("text").asText());
        assertTrue(replayed.path("text").asText().endsWith(". No second decision was applied."));

        // Unauthenticated callbacks change nothing.
        assertUnauthorised(harness, null, null,
                SlackFixtures.formBody(SlackFixtures.interaction(
                        SlackFixtures.OPERATOR_MEMBER, "aegis_approve", pending.ticketId())));
        assertUnauthorised(harness, String.valueOf(Instant.now().getEpochSecond()), "v0=deadbeef",
                SlackFixtures.formBody(SlackFixtures.interaction(
                        SlackFixtures.OPERATOR_MEMBER, "aegis_approve", pending.ticketId())));
        assertUnauthorised(harness, String.valueOf(Instant.now().minusSeconds(301).getEpochSecond()),
                SlackFixtures.signature(String.valueOf(Instant.now().minusSeconds(301).getEpochSecond()), "payload=x"),
                "payload=x");
        assertUnauthorised(harness, String.valueOf(Instant.now().getEpochSecond()),
                SlackFixtures.signature(String.valueOf(Instant.now().getEpochSecond()), "payload=%7B%7D"),
                "payload=%7B%7D");
        assertUnauthorised(harness, String.valueOf(Instant.now().getEpochSecond()),
                SlackFixtures.signature(String.valueOf(Instant.now().getEpochSecond()),
                        SlackFixtures.formBody("{\"type\":\"view_submission\",\"user\":{\"id\":\"U\"}}")),
                SlackFixtures.formBody("{\"type\":\"view_submission\",\"user\":{\"id\":\"U\"}}"));
        assertUnauthorised(harness, String.valueOf(Instant.now().getEpochSecond()),
                SlackFixtures.signature(String.valueOf(Instant.now().getEpochSecond()),
                        SlackFixtures.formBody("{\"type\":\"block_actions\",\"actions\":"
                                + "[{\"action_id\":\"aegis_approve\",\"value\":\"appr_x\"}]}")),
                SlackFixtures.formBody("{\"type\":\"block_actions\",\"actions\":"
                        + "[{\"action_id\":\"aegis_approve\",\"value\":\"appr_x\"}]}"));
        assertUnauthorised(harness, String.valueOf(Instant.now().getEpochSecond()),
                SlackFixtures.signature(String.valueOf(Instant.now().getEpochSecond()),
                        SlackFixtures.formBody("{\"type\":\"block_actions\",\"user\":{\"id\":\"U\"},"
                                + "\"actions\":[{\"action_id\":\"other\",\"value\":\"x\"}]}")),
                SlackFixtures.formBody("{\"type\":\"block_actions\",\"user\":{\"id\":\"U\"},"
                        + "\"actions\":[{\"action_id\":\"other\",\"value\":\"x\"}]}"));
    }

    @Test
    @DisplayName("C-024: rejects a ticket through Slack and reports each authenticated outcome")
    void reportsRejectionUnknownTicketAndRefusedActors() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-slack-reject", "deploy_prod", "{}");

        HttpResponse<String> rejection = callback(harness, SlackFixtures.interaction(
                SlackFixtures.OPERATOR_MEMBER, "aegis_reject", pending.ticketId()));
        ContractAssertions.assertStatus(200, rejection);
        JsonNode rejected = GatewayHarness.json(rejection);
        assertTrue(rejected.path("replace_original").asBoolean(),
                () -> "Expected a channel-visible rejection, got: " + rejection.body());
        assertTrue(rejected.path("text").asText().startsWith(
                "Rejected by " + SlackFixtures.MAPPED_OPERATOR + " at "),
                () -> "Unexpected rejection text: " + rejected.path("text").asText());
        assertEquals(403, pending.response().get(10, TimeUnit.SECONDS).statusCode());

        JsonNode unknown = GatewayHarness.json(callback(harness, SlackFixtures.interaction(
                SlackFixtures.OPERATOR_MEMBER, "aegis_approve", "appr_00000000000000000000000000")));
        assertEquals(false, unknown.path("replace_original").asBoolean());
        assertEquals("That approval request no longer exists.", unknown.path("text").asText());

        JsonNode noValue = GatewayHarness.json(callback(harness, SlackFixtures.interaction(
                SlackFixtures.OPERATOR_MEMBER, "aegis_approve", null)));
        assertEquals(false, noValue.path("replace_original").asBoolean());
        assertEquals("This approval action carries no ticket identifier.", noValue.path("text").asText());

        JsonNode unmapped = GatewayHarness.json(callback(harness, SlackFixtures.interaction(
                SlackFixtures.UNMAPPED_MEMBER, "aegis_approve", pending.ticketId())));
        assertEquals("ephemeral", unmapped.path("response_type").asText());
        assertEquals("Your Slack account is not mapped to an AegisMCP operator. "
                + "Ask an administrator to add it to the approval operator map.", unmapped.path("text").asText());

        JsonNode viewer = GatewayHarness.json(callback(harness, SlackFixtures.interaction(
                SlackFixtures.VIEWER_MEMBER, "aegis_approve", pending.ticketId())));
        assertEquals("ephemeral", viewer.path("response_type").asText());
        assertEquals("Your operator role does not permit approval decisions. "
                + "An operator or admin role is required.", viewer.path("text").asText());

        // A refused actor leaves the ticket pending and reachable from the console queue.
        JsonNode queue = GatewayHarness.json(harness.get("/api/v1/approvals/pending", harness.operatorToken()));
        boolean stillPending = false;
        for (JsonNode ticket : queue.path("tickets")) {
            if ("agent-slack-reject".equals(ticket.path("agentId").asText())) {
                stillPending = "pending".equals(ticket.path("status").asText());
            }
        }
        assertTrue(stillPending, "A refused Slack actor leaves the ticket pending");
    }

    @Test
    @DisplayName("C-024: reports a ticket that reached its time-to-live")
    void reportsExpiredTicket() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().approvalTtl(Duration.ofSeconds(1)))) {
            GatewayHarness.PendingCall pending = harness.createPendingCall("agent-slack-expired", "deploy_prod", "{}");
            pending.response().get(15, TimeUnit.SECONDS);

            JsonNode expired = GatewayHarness.json(callback(harness, SlackFixtures.interaction(
                    SlackFixtures.OPERATOR_MEMBER, "aegis_approve", pending.ticketId())));
            assertTrue(expired.path("replace_original").asBoolean());
            assertTrue(expired.path("text").asText().startsWith("Expired at "),
                    () -> "Unexpected expiry text: " + expired.path("text").asText());
            assertTrue(expired.path("text").asText().endsWith(
                    ". The suspended call was denied. No second decision was applied."));
        }
    }

    @Test
    @DisplayName("C-024: answers 404 when no Slack workspace is configured")
    void answersNotFoundWithoutSlack() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().slackConfigured(false))) {
            HttpResponse<String> response = harness.postRaw(PATH, "application/x-www-form-urlencoded",
                    SlackFixtures.formBody(SlackFixtures.interaction(
                            SlackFixtures.OPERATOR_MEMBER, "aegis_approve", "appr_x")), Map.of());
            ContractAssertions.assertError(response, 404, "Not Found");
        }
    }

    @Test
    @DisplayName("C-024: answers 405 for a method other than POST")
    void answersMethodNotAllowed() throws Exception {
        HttpResponse<String> response = gateway().get(PATH, null);
        ContractAssertions.assertError(response, 405,
                "Method Not Allowed: only POST supported for Slack interactions");
    }

    private static HttpResponse<String> callback(GatewayHarness harness, String interaction) throws Exception {
        String body = SlackFixtures.formBody(interaction);
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        return harness.postRaw(PATH, "application/x-www-form-urlencoded", body,
                Map.of("X-Slack-Request-Timestamp", timestamp,
                        "X-Slack-Signature", SlackFixtures.signature(timestamp, body)));
    }

    private static void assertUnauthorised(
            GatewayHarness harness,
            String timestamp,
            String signature,
            String body
    ) throws Exception {
        Map<String, String> headers = new java.util.HashMap<>();
        if (timestamp != null) {
            headers.put("X-Slack-Request-Timestamp", timestamp);
        }
        if (signature != null) {
            headers.put("X-Slack-Signature", signature);
        }
        HttpResponse<String> response = harness.postRaw(PATH,
                "application/x-www-form-urlencoded", body, headers);
        ContractAssertions.assertError(response, 401, "Unauthorized");
        ContractAssertions.assertNoInternalDetail(response);
    }
}
