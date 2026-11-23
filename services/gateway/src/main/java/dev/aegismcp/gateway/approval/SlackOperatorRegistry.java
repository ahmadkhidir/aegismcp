package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.config.ConfigurationException;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Maps a Slack workspace member to the console operator session that resolves their approval
 * decisions.
 *
 * <p>FEAT-006 seals the mapped operator identity as the resolving approver and refuses a mapped
 * operator that does not hold the {@code operator} or {@code admin} role. The mapping is deployment
 * configuration; an unmapped Slack user is never trusted and never inherits a role.
 *
 * <p>Anchors: FEAT-006, C-004, C-014.
 */
public final class SlackOperatorRegistry {

    /** Roles that may resolve an approval decision (C-004, C-014). */
    private static final Set<String> DECIDING_ROLES = Set.of("operator", "admin");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** One mapped Slack member and the console operator identity and roles they act with. */
    public record SlackOperator(String slackUserId, String operator, Set<String> roles) {

        public SlackOperator {
            if (slackUserId == null || slackUserId.isBlank()) {
                throw new IllegalArgumentException("slackUserId must not be blank");
            }
            if (operator == null || operator.isBlank()) {
                throw new IllegalArgumentException("operator must not be blank");
            }
            roles = roles != null ? Set.copyOf(roles) : Set.of();
        }

        /** True when the mapped roles include the contract's operator or admin role. */
        public boolean canDecide() {
            return roles.stream().anyMatch(DECIDING_ROLES::contains);
        }
    }

    private final Map<String, SlackOperator> bySlackUser;

    private SlackOperatorRegistry(Map<String, SlackOperator> bySlackUser) {
        this.bySlackUser = Map.copyOf(bySlackUser);
    }

    public static SlackOperatorRegistry empty() {
        return new SlackOperatorRegistry(Map.of());
    }

    /**
     * Parses the operator map from its JSON array form, for example
     * {@code [{"slackUserId":"U024BE7LH","operator":"elena@example.com","roles":["operator"]}]}.
     * A malformed document names {@code key} and fails startup rather than silently dropping a
     * mapping that a reviewer relies on.
     */
    public static SlackOperatorRegistry parse(String json, String key) {
        if (json == null || json.isBlank()) {
            return empty();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (Exception e) {
            throw new ConfigurationException(key + " must be a JSON array of operator mappings", e);
        }
        if (root == null || !root.isArray()) {
            throw new ConfigurationException(key + " must be a JSON array of operator mappings");
        }

        Map<String, SlackOperator> mappings = new LinkedHashMap<>();
        for (JsonNode entry : root) {
            if (entry == null || !entry.isObject()) {
                throw new ConfigurationException(key + " entries must be objects");
            }
            String slackUserId = text(entry, "slackUserId");
            String operator = text(entry, "operator");
            if (slackUserId == null || operator == null) {
                throw new ConfigurationException(
                        key + " entries require both slackUserId and operator");
            }
            Set<String> roles = new LinkedHashSet<>();
            JsonNode rolesNode = entry.get("roles");
            if (rolesNode != null && rolesNode.isArray()) {
                for (JsonNode role : rolesNode) {
                    if (role != null && role.isTextual() && !role.asText().isBlank()) {
                        roles.add(role.asText().trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
            mappings.put(slackUserId, new SlackOperator(slackUserId, operator, roles));
        }
        return new SlackOperatorRegistry(mappings);
    }

    private static String text(JsonNode entry, String field) {
        JsonNode value = entry.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            return null;
        }
        return value.asText().trim();
    }

    /** The operator mapped to the acting Slack user, or empty when the user is not mapped. */
    public Optional<SlackOperator> find(String slackUserId) {
        if (slackUserId == null || slackUserId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(bySlackUser.get(slackUserId));
    }

    public boolean isEmpty() {
        return bySlackUser.isEmpty();
    }
}
