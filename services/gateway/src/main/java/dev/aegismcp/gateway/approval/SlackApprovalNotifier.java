package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;

/**
 * Posts the interactive Slack approval message described by FEAT-006.
 *
 * <p>The message carries an Approve and a Reject button whose action identifiers are exactly
 * {@code aegis_approve} and {@code aegis_reject} and whose value is the approval ticket token. Every
 * click is delivered by Slack to {@code POST /api/v1/integrations/slack/interactions}, where
 * {@link SlackApprovalCallback} authenticates it and resolves the ticket through the same path as
 * the console.
 *
 * <p>Anchors: FEAT-006.
 */
public final class SlackApprovalNotifier implements ApprovalNotificationChannel {

    public static final String ACTION_APPROVE = "aegis_approve";
    public static final String ACTION_REJECT = "aegis_reject";

    private static final String CHANNEL_NAME = "slack";

    private final URI webhookUrl;
    private final HttpClient client;
    private final Duration requestTimeout;
    private final ObjectMapper mapper;

    public SlackApprovalNotifier(URI webhookUrl, HttpClient client, Duration requestTimeout) {
        this(webhookUrl, client, requestTimeout, JsonRpcCodec.getInstance().getMapper());
    }

    public SlackApprovalNotifier(URI webhookUrl, HttpClient client, Duration requestTimeout,
                                 ObjectMapper mapper) {
        this.webhookUrl = Objects.requireNonNull(webhookUrl, "webhookUrl must not be null");
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
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
        payload.put("text", "Approval required: " + notification.toolName()
                + " requested by " + notification.agentId());

        ArrayNode blocks = payload.putArray("blocks");
        blocks.add(sectionText(detailsText(notification)));
        blocks.add(sectionText(argumentsText(notification)));

        ArrayNode elements = blocks.addObject()
                .put("type", "actions")
                .put("block_id", "aegis_approval")
                .putArray("elements");
        elements.addObject()
                .put("type", "button")
                .put("action_id", ACTION_APPROVE)
                .put("style", "primary")
                .put("value", notification.ticketId())
                .set("text", mapper.createObjectNode()
                        .put("type", "plain_text")
                        .put("text", "Approve"));
        elements.addObject()
                .put("type", "button")
                .put("action_id", ACTION_REJECT)
                .put("style", "danger")
                .put("value", notification.ticketId())
                .set("text", mapper.createObjectNode()
                        .put("type", "plain_text")
                        .put("text", "Reject"));
        return payload;
    }

    private ObjectNode sectionText(String mrkdwn) {
        return mapper.createObjectNode()
                .put("type", "section")
                .set("text", mapper.createObjectNode()
                        .put("type", "mrkdwn")
                        .put("text", mrkdwn));
    }

    private static String detailsText(ApprovalNotification notification) {
        StringBuilder text = new StringBuilder();
        text.append(":rotating_light: *Approval required*\n")
                .append("*Tool:* `").append(notification.toolName()).append("`\n")
                .append("*Agent:* `").append(notification.agentId()).append("`\n")
                .append("*Policy:* `")
                .append(notification.triggerPolicyId() != null ? notification.triggerPolicyId() : "default")
                .append("`\n");
        if (notification.agentIntent() != null) {
            text.append("*Agent intent:* ").append(notification.agentIntent()).append('\n');
        }
        text.append("*Ticket:* `").append(notification.ticketId()).append("`\n")
                .append("*Expires:* ").append(notification.expiresAt());
        return text.toString();
    }

    private static String argumentsText(ApprovalNotification notification) {
        return "*Arguments:* ```" + notification.argumentsPayload() + "```";
    }
}
