package dev.aegismcp.e2e.fixtures;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Slack signing material and payload construction for C-024. The signature is computed exactly as
 * the contract states: {@code v0=} plus the lowercase hex HMAC-SHA256 of
 * {@code v0:<timestamp>:<raw body>} keyed by the workspace signing secret.
 */
public final class SlackFixtures {

    public static final String SIGNING_SECRET = "e2e-slack-signing-secret";
    public static final String OPERATOR_MEMBER = "U_E2E_OPERATOR";
    public static final String VIEWER_MEMBER = "U_E2E_VIEWER";
    public static final String UNMAPPED_MEMBER = "U_E2E_UNMAPPED";
    public static final String MAPPED_OPERATOR = "slack.operator@aegis.test";

    public static final String OPERATOR_MAP;

    static {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode operators = mapper.createArrayNode();
        operators.add(operator(mapper, OPERATOR_MEMBER, MAPPED_OPERATOR, "operator"));
        operators.add(operator(mapper, VIEWER_MEMBER, "slack.viewer@aegis.test", "viewer"));
        try {
            OPERATOR_MAP = mapper.writeValueAsString(operators);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private SlackFixtures() {
    }

    private static ObjectNode operator(ObjectMapper mapper, String slackUserId, String operator, String role) {
        ObjectNode node = mapper.createObjectNode();
        node.put("slackUserId", slackUserId);
        node.put("operator", operator);
        ArrayNode roles = mapper.createArrayNode();
        roles.add(role);
        node.set("roles", roles);
        return node;
    }

    /** The {@code application/x-www-form-urlencoded} body carrying the interaction payload. */
    public static String formBody(String payloadJson) {
        return "payload=" + URLEncoder.encode(payloadJson, StandardCharsets.UTF_8);
    }

    /** The interaction payload for one approval button click. */
    public static String interaction(String slackUserId, String actionId, String ticketId) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode interaction = mapper.createObjectNode();
        interaction.put("type", "block_actions");
        ObjectNode user = mapper.createObjectNode();
        user.put("id", slackUserId);
        interaction.set("user", user);
        ArrayNode actions = mapper.createArrayNode();
        ObjectNode action = mapper.createObjectNode();
        action.put("action_id", actionId);
        if (ticketId != null) {
            action.put("value", ticketId);
        }
        actions.add(action);
        interaction.set("actions", actions);
        try {
            return mapper.writeValueAsString(interaction);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String signature(String timestamp, String rawBody) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SIGNING_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(("v0:" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
            mac.update(rawBody.getBytes(StandardCharsets.UTF_8));
            return "v0=" + HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
