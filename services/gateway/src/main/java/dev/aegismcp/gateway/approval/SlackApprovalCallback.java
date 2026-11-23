package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import io.netty.handler.codec.http.QueryStringDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Authenticates and applies Slack interactive approval callbacks (FEAT-006).
 *
 * <p>Every callback is authenticated with the workspace signing secret: the gateway recomputes
 * {@code v0=} plus the HMAC-SHA256 of {@code v0:<timestamp>:<raw body>} and compares it in constant
 * time with {@code X-Slack-Signature}, refusing a timestamp more than 300 seconds from its own
 * clock. An unauthenticated callback changes nothing.
 *
 * <p>An authenticated callback resolves through the same {@link ApprovalManager} path as the
 * console. The Slack member is mapped to an operator session, that operator identity is sealed as
 * the resolving approver, and a mapped member without the {@code operator} or {@code admin} role is
 * refused. Slack redelivers any non-200 answer, so every authenticated callback is answered 200 and
 * carries the outcome already recorded rather than applying a second decision.
 *
 * <p>Anchors: FEAT-006, C-004, C-014.
 */
public final class SlackApprovalCallback {

    private static final Logger logger = LoggerFactory.getLogger(SlackApprovalCallback.class);

    /** Slack slackens a request timestamp by this much before the callback is refused. */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(300);

    /** Slack's rejection reason for a button click that rejects the suspended call. */
    public static final String SLACK_REJECTION_REASON = "SLACK_REJECTED";

    private final ApprovalNotificationConfig.Slack slack;
    private final ApprovalManager approvalManager;
    private final ObjectMapper mapper;
    private final Clock clock;

    public SlackApprovalCallback(
            ApprovalNotificationConfig.Slack slack,
            ApprovalManager approvalManager
    ) {
        this(slack, approvalManager, JsonRpcCodec.getInstance().getMapper(), Clock.systemUTC());
    }

    public SlackApprovalCallback(
            ApprovalNotificationConfig.Slack slack,
            ApprovalManager approvalManager,
            ObjectMapper mapper,
            Clock clock
    ) {
        this.slack = Objects.requireNonNull(slack, "slack must not be null");
        this.approvalManager = Objects.requireNonNull(approvalManager, "approvalManager must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    /** A response body and status for the Slack endpoint. */
    public record Result(int status, JsonNode body) {
    }

    /**
     * Processes one callback. {@code timestampHeader} and {@code signatureHeader} are the
     * {@code X-Slack-Request-Timestamp} and {@code X-Slack-Signature} values; {@code rawBody} is the
     * exact received body because the signature covers its bytes.
     */
    public Result handle(String timestampHeader, String signatureHeader, byte[] rawBody) {
        byte[] body = rawBody != null ? rawBody : new byte[0];
        if (!verify(timestampHeader, signatureHeader, body)) {
            return unauthorized();
        }

        JsonNode interaction = readInteraction(body);
        if (interaction == null || !"block_actions".equals(text(interaction, "type"))) {
            return unauthorized();
        }

        JsonNode user = interaction.get("user");
        String slackUserId = user != null ? text(user, "id") : null;
        if (slackUserId == null) {
            return unauthorized();
        }

        JsonNode action = findApprovalAction(interaction.get("actions"));
        if (action == null) {
            return unauthorized();
        }

        String ticketId = text(action, "value");
        if (ticketId == null) {
            return ok(false, "This approval action carries no ticket identifier.");
        }

        Optional<SlackOperatorRegistry.SlackOperator> mapped = slack.operators().find(slackUserId);
        if (mapped.isEmpty()) {
            return ephemeral("Your Slack account is not mapped to an AegisMCP operator. "
                    + "Ask an administrator to add it to the approval operator map.");
        }
        SlackOperatorRegistry.SlackOperator operator = mapped.get();
        if (!operator.canDecide()) {
            return ephemeral("Your operator role does not permit approval decisions. "
                    + "An operator or admin role is required.");
        }

        boolean approve = SlackApprovalNotifier.ACTION_APPROVE.equals(text(action, "action_id"));

        try {
            ApprovalTicket ticket = approve
                    ? approvalManager.approve(ticketId, operator.operator())
                    : approvalManager.reject(ticketId, operator.operator(), SLACK_REJECTION_REASON);
            logger.info("Slack approval callback applied a {} decision", approve ? "approval" : "rejection");
            return ok(true, (approve ? "Approved" : "Rejected")
                    + " by " + operator.operator() + " at " + ticket.processedAt());
        } catch (ApprovalException.TicketAlreadyResolvedException e) {
            return ok(true, recordedOutcome(ticketId));
        } catch (ApprovalException.TicketExpiredException e) {
            return ok(true, expiredOutcome(ticketId));
        } catch (ApprovalException.TicketNotFoundException e) {
            return ok(false, "That approval request no longer exists.");
        } catch (ApprovalException e) {
            return ephemeral("The approval decision could not be applied.");
        } catch (RuntimeException e) {
            // The callback is authenticated, so Slack must still see 200 or it will redeliver; the
            // failure class is logged without the ticket token or the actor identity.
            logger.warn("Slack approval callback failed to apply a decision: {}",
                    e.getClass().getSimpleName());
            return ephemeral("The approval decision could not be applied.");
        }
    }

    /** The decision already recorded for the ticket, so a replay changes nothing. */
    private String recordedOutcome(String ticketId) {
        return approvalManager.getTicket(ticketId)
                .map(ticket -> {
                    String decision = ApprovalStatus.APPROVED.getValue().equalsIgnoreCase(ticket.status())
                            ? "Approved"
                            : ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(ticket.status())
                                    ? "Expired"
                                    : "Rejected";
                    String reviewer = ticket.reviewedBy() != null ? ticket.reviewedBy() : "system";
                    String at = ticket.processedAt() != null ? ticket.processedAt() : ticket.expiresAt();
                    return "Already " + decision.toLowerCase(Locale.ROOT) + " by " + reviewer
                            + " at " + at + ". No second decision was applied.";
                })
                .orElse("That approval request no longer exists.");
    }

    private String expiredOutcome(String ticketId) {
        return approvalManager.getTicket(ticketId)
                .map(ticket -> "Expired at " + ticket.expiresAt()
                        + ". The suspended call was denied. No second decision was applied.")
                .orElse("That approval request no longer exists.");
    }

    private JsonNode readInteraction(byte[] body) {
        String text = new String(body, StandardCharsets.UTF_8);
        String trimmed = text.stripLeading();
        String payload = null;
        if (trimmed.startsWith("{")) {
            payload = trimmed;
        } else if (!text.isBlank()) {
            QueryStringDecoder form = new QueryStringDecoder("?" + text);
            var values = form.parameters().get("payload");
            if (values != null && !values.isEmpty()) {
                payload = values.get(0);
            }
        }
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            return mapper.readTree(payload);
        } catch (Exception e) {
            return null;
        }
    }

    private JsonNode findApprovalAction(JsonNode actions) {
        if (actions == null || !actions.isArray()) {
            return null;
        }
        for (JsonNode action : actions) {
            String actionId = text(action, "action_id");
            if (SlackApprovalNotifier.ACTION_APPROVE.equals(actionId)
                    || SlackApprovalNotifier.ACTION_REJECT.equals(actionId)) {
                return action;
            }
        }
        return null;
    }

    /**
     * Recomputes the Slack signature over the exact body bytes. The comparison is constant time so a
     * caller cannot learn the expected digest one byte at a time.
     */
    boolean verify(String timestampHeader, String signatureHeader, byte[] rawBody) {
        if (timestampHeader == null || signatureHeader == null) {
            return false;
        }
        long timestamp;
        try {
            timestamp = Long.parseLong(timestampHeader.trim());
        } catch (NumberFormatException e) {
            return false;
        }
        long now = Instant.now(clock).getEpochSecond();
        if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW.toSeconds()) {
            return false;
        }

        String expected = "v0=" + hmacHex(timestampHeader.trim(), rawBody);
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                signatureHeader.trim().getBytes(StandardCharsets.US_ASCII));
    }

    private String hmacHex(String timestamp, byte[] rawBody) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    slack.signingSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(("v0:" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
            mac.update(rawBody);
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            // An unavailable HMAC algorithm must fail the callback closed, never accept it.
            logger.error("Slack callback signature could not be computed", e);
            return "";
        }
    }

    private Result unauthorized() {
        return new Result(401, error("Unauthorized"));
    }

    private ObjectNode error(String message) {
        ObjectNode node = mapper.createObjectNode();
        node.put("error", message);
        return node;
    }

    /** A message that replaces the Slack approval message so the channel shows the outcome. */
    private Result ok(boolean replaceOriginal, String message) {
        ObjectNode node = mapper.createObjectNode();
        node.put("replace_original", replaceOriginal);
        node.put("text", message);
        return new Result(200, node);
    }

    /** A message only the acting Slack member sees; the channel message is left untouched. */
    private Result ephemeral(String message) {
        ObjectNode node = mapper.createObjectNode();
        node.put("response_type", "ephemeral");
        node.put("text", message);
        return new Result(200, node);
    }

    private static String text(JsonNode node, String field) {
        if (node == null || !node.isObject()) {
            return null;
        }
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            return null;
        }
        return value.asText().trim();
    }
}
