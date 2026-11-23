package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;

/**
 * Posts a machine-readable JSON notification to an operator webhook (FEAT-006).
 *
 * <p>The payload uses the {@code approval_ticket_created} event named by EVT-008 and repeats the
 * same masked ticket view the console queue shows. When a console base URL is configured, approve
 * and reject links are included so a receiver can act without a bespoke integration.
 *
 * <p>Anchors: FEAT-006, EVT-008.
 */
public final class WebhookApprovalNotifier implements ApprovalNotificationChannel {

    private static final String CHANNEL_NAME = "webhook";
    private static final String EVENT_NAME = "approval_ticket_created";

    private final URI webhookUrl;
    private final HttpClient client;
    private final Duration requestTimeout;
    private final URI consoleBaseUrl;
    private final ObjectMapper mapper;

    public WebhookApprovalNotifier(URI webhookUrl, HttpClient client, Duration requestTimeout,
                                   URI consoleBaseUrl) {
        this(webhookUrl, client, requestTimeout, consoleBaseUrl, JsonRpcCodec.getInstance().getMapper());
    }

    public WebhookApprovalNotifier(URI webhookUrl, HttpClient client, Duration requestTimeout,
                                   URI consoleBaseUrl, ObjectMapper mapper) {
        this.webhookUrl = Objects.requireNonNull(webhookUrl, "webhookUrl must not be null");
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
        this.consoleBaseUrl = consoleBaseUrl;
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
    }

    @Override
    public String name() {
        return CHANNEL_NAME;
    }

    @Override
    public void deliver(ApprovalNotification notification) throws Exception {
        byte[] payload = mapper.writeValueAsBytes(buildPayload(notification));
        ApprovalNotificationHttp.postJson(client, requestTimeout, webhookUrl, payload);
    }

    private ObjectNode buildPayload(ApprovalNotification notification) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("event", EVENT_NAME);

        ObjectNode ticket = payload.putObject("ticket");
        ticket.put("id", notification.ticketId());
        ticket.put("agentId", notification.agentId());
        ticket.put("toolName", notification.toolName());
        ticket.put("argumentsPayload", notification.argumentsPayload());
        ticket.put("triggerPolicyId", notification.triggerPolicyId());
        if (notification.agentIntent() != null) {
            ticket.put("agentIntent", notification.agentIntent());
        } else {
            ticket.putNull("agentIntent");
        }
        ticket.put("status", ApprovalStatus.PENDING.getValue());
        ticket.put("createdAt", notification.createdAt());
        ticket.put("expiresAt", notification.expiresAt());
        ticket.put("riskScore", notification.riskScore());

        if (consoleBaseUrl != null) {
            ObjectNode links = payload.putObject("links");
            links.put("approve", approveLink(notification.ticketId()));
            links.put("reject", rejectLink(notification.ticketId()));
        }
        return payload;
    }

    private String approveLink(String ticketId) {
        return baseWithSlash() + "api/v1/approvals/" + ticketId + "/approve";
    }

    private String rejectLink(String ticketId) {
        return baseWithSlash() + "api/v1/approvals/" + ticketId + "/reject";
    }

    private String baseWithSlash() {
        String value = consoleBaseUrl.toString();
        return value.endsWith("/") ? value : value + "/";
    }
}
