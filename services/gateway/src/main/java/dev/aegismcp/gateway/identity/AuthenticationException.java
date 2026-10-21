package dev.aegismcp.gateway.identity;

/**
 * Exception thrown when cryptographic authentication or credential verification fails.
 * Maps to JSON-RPC -32000 Authentication Failed and HTTP 401 Unauthorized.
 * Anchors: FEAT-009, C-001.
 */
public class AuthenticationException extends RuntimeException {

    private final int errorCode;

    public AuthenticationException(String message) {
        this(message, null, -32000);
    }

    public AuthenticationException(String message, Throwable cause) {
        this(message, cause, -32000);
    }

    public AuthenticationException(String message, Throwable cause, int errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
