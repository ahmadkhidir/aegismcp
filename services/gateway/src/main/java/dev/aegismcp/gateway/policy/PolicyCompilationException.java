package dev.aegismcp.gateway.policy;

/**
 * Thrown when declarative YAML policy fails syntax validation or AST compilation.
 * Anchors: FEAT-002, C-006.
 */
public class PolicyCompilationException extends RuntimeException {

    private final String policyId;

    public PolicyCompilationException(String message) {
        this(message, null, null);
    }

    public PolicyCompilationException(String message, Throwable cause) {
        this(message, null, cause);
    }

    public PolicyCompilationException(String message, String policyId, Throwable cause) {
        super(message, cause);
        this.policyId = policyId;
    }

    public String getPolicyId() {
        return policyId;
    }
}
