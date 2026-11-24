package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.handler.codec.http.HttpResponseStatus;

import java.util.Locale;

/**
 * Standardized JSON-RPC 2.0 error object with the C-001 machine code and HTTP status mapping.
 *
 * <p>C-001 fixes both the JSON-RPC {@code code} and a machine-readable family in {@code data.code}
 * for every failure row. Two rows can share a numeric code while differing in machine code and HTTP
 * status — an internal failure and an upstream failure are both {@code -32603} — so the status is
 * resolved from the machine code first and the numeric code is the fallback for a peer-authored
 * error that carries no machine code.
 *
 * <p>Anchors: FEAT-001, C-001.
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

    // C-001 machine codes carried in data.code
    public static final String MACHINE_PARSE_ERROR = "PARSE_ERROR";
    public static final String MACHINE_INVALID_REQUEST = "INVALID_REQUEST";
    public static final String MACHINE_SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED";
    public static final String MACHINE_AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
    public static final String MACHINE_TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED";
    public static final String MACHINE_ARGUMENT_CONSTRAINT_VIOLATED = "ARGUMENT_CONSTRAINT_VIOLATED";
    public static final String MACHINE_PATH_TRAVERSAL = "PATH_TRAVERSAL";
    public static final String MACHINE_SQL_INJECTION = "SQL_INJECTION";
    public static final String MACHINE_TOOL_CHAIN_BLOCKED = "TOOL_CHAIN_BLOCKED";
    public static final String MACHINE_APPROVAL_DENIED = "APPROVAL_DENIED";
    public static final String MACHINE_APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT";
    public static final String MACHINE_INVOCATION_VELOCITY_EXCEEDED = "INVOCATION_VELOCITY_EXCEEDED";
    public static final String MACHINE_INTERNAL_ERROR = "INTERNAL_ERROR";
    public static final String MACHINE_UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE";
    public static final String MACHINE_APPROVAL_SERVICE_UNAVAILABLE = "APPROVAL_SERVICE_UNAVAILABLE";

    public JsonRpcError(int code, String message) {
        this(code, message, null);
    }

    public static JsonRpcError parseError(String details) {
        return new JsonRpcError(PARSE_ERROR, "Parse error: " + details, machineData(MACHINE_PARSE_ERROR));
    }

    public static JsonRpcError invalidRequest(String details) {
        return new JsonRpcError(INVALID_REQUEST, "Invalid Request: " + details,
                machineData(MACHINE_INVALID_REQUEST));
    }

    public static JsonRpcError methodNotFound(String method) {
        return new JsonRpcError(METHOD_NOT_FOUND, "Method not found: " + method);
    }

    /**
     * C-001 maps arguments that fail the target tool's published JSON schema to HTTP {@code 400}
     * with {@code -32602 Invalid params} and machine code {@code SCHEMA_VALIDATION_FAILED}.
     */
    public static JsonRpcError schemaValidationFailed(String details) {
        return new JsonRpcError(INVALID_PARAMS, "Invalid params: " + details,
                machineData(MACHINE_SCHEMA_VALIDATION_FAILED));
    }

    /**
     * C-001 maps an argument that violates a declared constraint to HTTP {@code 403} with
     * {@code -32001 Policy Violation} and machine code {@code ARGUMENT_CONSTRAINT_VIOLATED}.
     */
    public static JsonRpcError argumentConstraintViolated(String details) {
        return policyViolation(MACHINE_ARGUMENT_CONSTRAINT_VIOLATED, details);
    }

    public static JsonRpcError internalError(String details) {
        return new JsonRpcError(INTERNAL_ERROR, "Internal error: " + details,
                machineData(MACHINE_INTERNAL_ERROR));
    }

    public static JsonRpcError authenticationFailed(String details) {
        return new JsonRpcError(AUTHENTICATION_FAILED, "Authentication Failed: " + details,
                machineData(MACHINE_AUTHENTICATION_FAILED));
    }

    public static JsonRpcError policyViolation(String details) {
        return policyViolation(MACHINE_TOOL_NOT_PERMITTED, details);
    }

    /**
     * Builds a policy-family failure whose contract machine code is explicit. C-001 assigns
     * several machine codes to {@code -32001}; the caller knows which rule fired.
     */
    public static JsonRpcError policyViolation(String machineCode, String details) {
        return new JsonRpcError(POLICY_VIOLATION, "Policy Violation: " + details, machineData(machineCode));
    }

    public static JsonRpcError approvalTimedOut(String details) {
        return new JsonRpcError(APPROVAL_TIMED_OUT, "Approval Timed Out: " + details,
                machineData(MACHINE_APPROVAL_TIMEOUT));
    }

    public static JsonRpcError rateLimited(String details) {
        return new JsonRpcError(RATE_LIMITED, "Rate Limited: " + details,
                machineData(MACHINE_INVOCATION_VELOCITY_EXCEEDED));
    }

    /**
     * C-001 maps an unreachable, crashed, timed-out, or non-answering upstream to HTTP {@code 502}
     * with {@code -32603 Internal error} and machine code {@code UPSTREAM_UNAVAILABLE}. The upstream
     * detail is never exposed to the agent.
     */
    public static JsonRpcError upstreamUnavailable(String details) {
        return new JsonRpcError(INTERNAL_ERROR, "Internal error: " + details,
                machineData(MACHINE_UPSTREAM_UNAVAILABLE));
    }

    /** The C-001 machine code carried in {@code data.code}, or {@code null} when absent. */
    public String machineCode() {
        if (data == null || !data.isObject()) {
            return null;
        }
        JsonNode codeNode = data.get("code");
        return codeNode != null && codeNode.isTextual() ? codeNode.asText() : null;
    }

    /**
     * Maps the error to its HTTP status per C-001, resolving the machine code first because two
     * rows share the {@code -32603} numeric code.
     */
    public HttpResponseStatus toHttpStatus() {
        String machine = machineCode();
        if (machine != null) {
            switch (machine.toUpperCase(Locale.ROOT)) {
                case MACHINE_AUTHENTICATION_FAILED -> {
                    return HttpResponseStatus.UNAUTHORIZED;
                }
                case MACHINE_TOOL_NOT_PERMITTED, MACHINE_ARGUMENT_CONSTRAINT_VIOLATED,
                        MACHINE_PATH_TRAVERSAL, MACHINE_SQL_INJECTION, MACHINE_TOOL_CHAIN_BLOCKED,
                        MACHINE_APPROVAL_DENIED -> {
                    return HttpResponseStatus.FORBIDDEN;
                }
                case MACHINE_APPROVAL_TIMEOUT -> {
                    return HttpResponseStatus.REQUEST_TIMEOUT;
                }
                case MACHINE_APPROVAL_SERVICE_UNAVAILABLE -> {
                    return HttpResponseStatus.SERVICE_UNAVAILABLE;
                }
                case MACHINE_INVOCATION_VELOCITY_EXCEEDED -> {
                    return HttpResponseStatus.TOO_MANY_REQUESTS;
                }
                case MACHINE_UPSTREAM_UNAVAILABLE -> {
                    return HttpResponseStatus.BAD_GATEWAY;
                }
                case MACHINE_PARSE_ERROR, MACHINE_INVALID_REQUEST, MACHINE_SCHEMA_VALIDATION_FAILED -> {
                    return HttpResponseStatus.BAD_REQUEST;
                }
                default -> {
                    // Fall through to the numeric mapping for codes this build does not name.
                }
            }
        }
        return switch (code) {
            case AUTHENTICATION_FAILED -> HttpResponseStatus.UNAUTHORIZED; // 401
            case POLICY_VIOLATION -> HttpResponseStatus.FORBIDDEN; // 403
            case APPROVAL_TIMED_OUT -> HttpResponseStatus.REQUEST_TIMEOUT; // 408
            case RATE_LIMITED -> HttpResponseStatus.TOO_MANY_REQUESTS; // 429
            case PARSE_ERROR, INVALID_REQUEST, INVALID_PARAMS -> HttpResponseStatus.BAD_REQUEST; // 400
            case METHOD_NOT_FOUND -> HttpResponseStatus.NOT_FOUND; // 404
            default -> HttpResponseStatus.INTERNAL_SERVER_ERROR; // 500
        };
    }

    private static ObjectNode machineData(String machineCode) {
        ObjectNode data = JsonNodeFactory.instance.objectNode();
        data.put("code", machineCode);
        return data;
    }
}
