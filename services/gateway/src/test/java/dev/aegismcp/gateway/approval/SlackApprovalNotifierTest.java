package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.sun.net.httpserver.HttpServer;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the Slack interactive approval message: the action identifiers and ticket value FEAT-006
 * fixes, and that nothing secret reaches the posted payload.
 *
 * <p>Anchors: FEAT-006.
 */
class SlackApprovalNotifierTest {

    private static final String TICKET_ID = TestCredentials.ticketId();
    private static final String PROVIDER_KEY = TestCredentials.providerKey();

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private final AtomicReference<String> capturedBody = new AtomicReference<>();
    private final AtomicInteger responseStatus = new AtomicInteger(200);
    private HttpServer server;
    private URI webhookUri;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/slack", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(responseStatus.get(), -1);
            exchange.close();
        });
        server.start();
        webhookUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/slack");
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private ApprovalNotification notification() {
        ApprovalTicket ticket = new ApprovalTicket(
                TICKET_ID,
                "agent-pay",
                "issue_refund",
                JsonNodeFactory.instance.objectNode()
                        .put("secret", PROVIDER_KEY)
                        .put("amount", 4200),
                88.0,
                ApprovalStatus.PENDING.getValue(),
                "2026-11-23T10:00:00Z",
                "2026-11-23T10:05:00Z",
                null, null, "pol_finance", "Refund the disputed charge", null
        );
        return ApprovalNotification.from(ticket);
    }

    @Test
    @DisplayName("FEAT-006: the Slack message carries Approve and Reject buttons holding the ticket token")
    void postsInteractiveApprovalMessage() throws Exception {
        SlackApprovalNotifier notifier = new SlackApprovalNotifier(
                webhookUri, HttpClient.newHttpClient(), Duration.ofSeconds(5));

        notifier.deliver(notification());

        JsonNode payload = mapper.readTree(capturedBody.get());
        assertTrue(payload.get("text").asText().contains("issue_refund"));

        JsonNode actions = null;
        for (JsonNode block : payload.get("blocks")) {
            if ("actions".equals(block.get("type").asText())) {
                actions = block;
            }
        }
        assertNotNull(actions, "The message must carry an actions block");
        JsonNode buttons = actions.get("elements");
        assertEquals(2, buttons.size());

        assertEquals(SlackApprovalNotifier.ACTION_APPROVE, buttons.get(0).get("action_id").asText());
        assertEquals(TICKET_ID, buttons.get(0).get("value").asText());
        assertEquals(SlackApprovalNotifier.ACTION_REJECT, buttons.get(1).get("action_id").asText());
        assertEquals(TICKET_ID, buttons.get(1).get("value").asText());

        assertFalse(capturedBody.get().contains(PROVIDER_KEY),
                "A tool argument secret must never reach Slack");
        assertTrue(capturedBody.get().contains("Refund the disputed charge"));
    }

    @Test
    @DisplayName("FEAT-006: a non-2xx Slack answer fails the delivery so it can be retried")
    void nonSuccessResponseFailsDelivery() {
        responseStatus.set(500);
        SlackApprovalNotifier notifier = new SlackApprovalNotifier(
                webhookUri, HttpClient.newHttpClient(), Duration.ofSeconds(5));

        ApprovalNotificationHttp.DeliveryFailedException failure = assertThrows(
                ApprovalNotificationHttp.DeliveryFailedException.class,
                () -> notifier.deliver(notification()));
        assertEquals(500, failure.statusCode());
    }
}
