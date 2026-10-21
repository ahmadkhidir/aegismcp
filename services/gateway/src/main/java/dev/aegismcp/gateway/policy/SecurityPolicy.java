package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Declarative Policy-as-Code document entity.
 * Anchors: FEAT-002, schema.md#SecurityPolicy, C-005, C-006.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SecurityPolicy(
        @JsonProperty(value = "id", required = true) String id,
        @JsonProperty(value = "name", required = true) String name,
        @JsonProperty(value = "version", required = true) String version,
        @JsonProperty(value = "rawYaml", required = true) String rawYaml,
        @JsonProperty(value = "status", required = true) String status,
        @JsonProperty("gitCommitHash") String gitCommitHash,
        @JsonProperty(value = "createdAt", required = true) String createdAt
) {
    public static final String STATUS_ACTIVE = "active";
    public static final String STATUS_DRAFT = "draft";
    public static final String STATUS_ARCHIVED = "archived";

    public SecurityPolicy {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(version, "version must not be null");
        Objects.requireNonNull(rawYaml, "rawYaml must not be null");
        if (status == null || status.isBlank()) {
            status = STATUS_ACTIVE;
        }
        if (!STATUS_ACTIVE.equals(status) && !STATUS_DRAFT.equals(status) && !STATUS_ARCHIVED.equals(status)) {
            throw new IllegalArgumentException("Invalid status '" + status + "'. Allowed: active, draft, archived");
        }
        if (createdAt == null || createdAt.isBlank()) {
            createdAt = Instant.now().toString();
        }
    }

    public static SecurityPolicy of(String id, String name, String version, String rawYaml, String gitCommitHash) {
        return new SecurityPolicy(id, name, version, rawYaml, STATUS_ACTIVE, gitCommitHash, Instant.now().toString());
    }
}
