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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the operator webhook notification: the EVT-008 event, the masked ticket view, and the
 * console decision links derived from the configured base URL.
 *
 * <p>Anchors: FEAT-006, EVT-008.
 */
class WebhookApprovalNotifierTest {

    private static final String TICKET_ID = TestCredentials.ticketId();
    private static final String PROVIDER_KEY = TestCredentials.providerKey();

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private final AtomicReference<String> capturedBody = new AtomicReference<>();
    private HttpServer server;
    private URI webhookUri;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();
        webhookUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/hook");
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
                "agent-dba",
                "drop_database",
                JsonNodeFactory.instance.objectNode().put("secret", PROVIDER_KEY),
                91.0,
                ApprovalStatus.PENDING.getValue(),
                "2026-11-23T10:00:00Z",
                "2026-11-23T10:05:00Z",
                null, null, "pol_db", null, null
        );
        return ApprovalNotification.from(ticket);
    }

    @Test
    @DisplayName("FEAT-006 / EVT-008: the webhook posts the created event with a masked ticket view")
    void postsApprovalTicketCreatedEvent() throws Exception {
        WebhookApprovalNotifier notifier = new WebhookApprovalNotifier(
                webhookUri, HttpClient.newHttpClient(), Duration.ofSeconds(5),
                URI.create("https://console.example.com"));

        notifier.deliver(notification());

        JsonNode payload = mapper.readTree(capturedBody.get());
        assertEquals("approval_ticket_created", payload.get("event").asText());

        JsonNode ticket = payload.get("ticket");
        assertEquals(TICKET_ID, ticket.get("id").asText());
        assertEquals("drop_database", ticket.get("toolName").asText());
        assertEquals("pending", ticket.get("status").asText());
        assertEquals("pol_db", ticket.get("triggerPolicyId").asText());
        assertTrue(ticket.get("agentIntent").isNull());

        assertEquals(
                "https://console.example.com/api/v1/approvals/" + TICKET_ID + "/approve",
                payload.get("links").get("approve").asText());
        assertEquals(
                "https://console.example.com/api/v1/approvals/" + TICKET_ID + "/reject",
                payload.get("links").get("reject").asText());

        assertFalse(capturedBody.get().contains(PROVIDER_KEY),
                "A tool argument secret must never reach the operator webhook");
    }

    @Test
    @DisplayName("FEAT-006: without a console base URL the webhook omits decision links")
    void omitsLinksWithoutConsoleUrl() throws Exception {
        WebhookApprovalNotifier notifier = new WebhookApprovalNotifier(
                webhookUri, HttpClient.newHttpClient(), Duration.ofSeconds(5), null);

        notifier.deliver(notification());

        JsonNode payload = mapper.readTree(capturedBody.get());
        assertTrue(payload.get("links") == null);
    }
}
