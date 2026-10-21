package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.netty.handler.codec.http.HttpResponseStatus;

/**
 * Standardized JSON-RPC 2.0 error object with C-001 HTTP status mapping.
 * Anchors: FEAT-001, C-001.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JsonRpcError(
        @JsonProperty("code") int code,
        @JsonProperty("message") String message,
        @JsonProperty("data") JsonNode data
) {
    // Standard JSON-RPC 2.0 specification error codes
    public static final int PARSE_ERROR = -32700;
    public static final int INVALID_REQUEST = -32600;
    public static final int METHOD_NOT_FOUND = -32601;
    public static final int INVALID_PARAMS = -32602;
    public static final int INTERNAL_ERROR = -32603;

    // C-001 Zero-Trust security error codes
    public static final int AUTHENTICATION_FAILED = -32000;
    public static final int POLICY_VIOLATION = -32001;
    public static final int APPROVAL_TIMED_OUT = -32002;
    public static final int RATE_LIMITED = -32003;
    public static final int UPSTREAM_UNAVAILABLE = -32004;

    public JsonRpcError(int code, String message) {
        this(code, message, null);
    }

    public static JsonRpcError parseError(String details) {
        return new JsonRpcError(PARSE_ERROR, "Parse error: " + details);
    }

    public static JsonRpcError invalidRequest(String details) {
        return new JsonRpcError(INVALID_REQUEST, "Invalid Request: " + details);
    }

    public static JsonRpcError methodNotFound(String method) {
        return new JsonRpcError(METHOD_NOT_FOUND, "Method not found: " + method);
    }

    public static JsonRpcError invalidParams(String details) {
        return new JsonRpcError(INVALID_PARAMS, "Invalid params: " + details);
    }

    public static JsonRpcError internalError(String details) {
        return new JsonRpcError(INTERNAL_ERROR, "Internal error: " + details);
    }

    public static JsonRpcError authenticationFailed(String details) {
        return new JsonRpcError(AUTHENTICATION_FAILED, "Authentication Failed: " + details);
    }

    public static JsonRpcError policyViolation(String details) {
        return new JsonRpcError(POLICY_VIOLATION, "Policy Violation: " + details);
    }

    public static JsonRpcError approvalTimedOut(String details) {
        return new JsonRpcError(APPROVAL_TIMED_OUT, "Approval Timed Out: " + details);
    }

    public static JsonRpcError rateLimited(String details) {
        return new JsonRpcError(RATE_LIMITED, "Rate Limited: " + details);
    }

    public static JsonRpcError upstreamUnavailable(String details) {
        return new JsonRpcError(UPSTREAM_UNAVAILABLE, "Upstream Unavailable: " + details);
    }

    /**
     * Maps the JSON-RPC 2.0 error code to its HTTP status code per contract C-001.
     */
    public HttpResponseStatus toHttpStatus() {
        return switch (code) {
            case AUTHENTICATION_FAILED -> HttpResponseStatus.UNAUTHORIZED; // 401
            case POLICY_VIOLATION -> HttpResponseStatus.FORBIDDEN; // 403
            case APPROVAL_TIMED_OUT -> HttpResponseStatus.REQUEST_TIMEOUT; // 408
            case RATE_LIMITED -> HttpResponseStatus.TOO_MANY_REQUESTS; // 429
            case UPSTREAM_UNAVAILABLE -> HttpResponseStatus.BAD_GATEWAY; // 502
            case PARSE_ERROR, INVALID_REQUEST, INVALID_PARAMS -> HttpResponseStatus.BAD_REQUEST; // 400
            case METHOD_NOT_FOUND -> HttpResponseStatus.NOT_FOUND; // 404
            default -> HttpResponseStatus.INTERNAL_SERVER_ERROR; // 500
        };
    }
}
