package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;

/**
 * Data Transfer Objects for Policy Management API conforming to contracts C-005 and C-006.
 * Anchors: C-005, C-006.
 */
public final class PolicyDto {

    private PolicyDto() {}

    /**
     * Response payload for C-005 (GET /api/v1/policies).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyListResponse(
            @JsonProperty(value = "policies", required = true) List<SecurityPolicy> policies
    ) {
        public PolicyListResponse {
            Objects.requireNonNull(policies, "policies list must not be null");
        }
    }

    /**
     * Request payload for C-006 (POST /api/v1/policies).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CreatePolicyRequest(
            @JsonProperty(value = "name", required = true) String name,
            @JsonProperty(value = "version", required = true) String version,
            @JsonProperty(value = "rawYaml", required = true) String rawYaml,
            @JsonProperty("gitCommitHash") String gitCommitHash
    ) {
        public CreatePolicyRequest {
            Objects.requireNonNull(name, "name must not be null");
            Objects.requireNonNull(version, "version must not be null");
            Objects.requireNonNull(rawYaml, "rawYaml must not be null");
        }
    }

    /**
     * Response payload for C-006 (POST /api/v1/policies) with HTTP 201 Created.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CreatePolicyResponse(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "name", required = true) String name,
            @JsonProperty(value = "version", required = true) String version,
            @JsonProperty(value = "status", required = true) String status,
            @JsonProperty(value = "createdAt", required = true) String createdAt
    ) {
        public CreatePolicyResponse {
            Objects.requireNonNull(id, "id must not be null");
            Objects.requireNonNull(name, "name must not be null");
            Objects.requireNonNull(version, "version must not be null");
            Objects.requireNonNull(status, "status must not be null");
            Objects.requireNonNull(createdAt, "createdAt must not be null");
        }
    }

    /**
     * Standard error response body.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ErrorResponse(
            @JsonProperty(value = "error", required = true) String error,
            @JsonProperty("details") String details
    ) {
        public ErrorResponse(String error) {
            this(error, null);
        }
    }
}
