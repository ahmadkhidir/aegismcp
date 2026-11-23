package dev.aegismcp.gateway.config;

/**
 * Raised when gateway configuration is present but cannot be trusted: a value is malformed, a
 * referenced file cannot be read, or a setting needed by another present setting is missing.
 *
 * <p>The message always names the offending key so an operator can fix the deployment without
 * reading the source. Startup fails on this exception rather than defaulting to a development
 * value (NFR-027, NFR-021).
 */
public class ConfigurationException extends RuntimeException {

    public ConfigurationException(String message) {
        super(message);
    }

    public ConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
