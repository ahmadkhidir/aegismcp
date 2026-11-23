package dev.aegismcp.gateway.inspector;

import dev.aegismcp.gateway.identity.OidcTokenValidator;
import dev.aegismcp.gateway.identity.OidcValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;
import java.util.Set;

/**
 * Subscribes an enterprise operator to the live traffic stream.
 *
 * <p>C-002 accepts any of the four RBAC roles and is read-only, so the only decision here is whether
 * the presented credential verifies through the frozen OIDC validator and carries one of those
 * roles. The credential arrives either as an {@code Authorization: Bearer} token, for the console's
 * fetch-based event reader, or in the console session cookie, for a browser-native
 * {@code EventSource} that cannot set headers; a cookie is accepted only when its value is itself an
 * OIDC token that passes the same signature, issuer, audience, and expiry checks. No role is ever
 * inferred from token text, and a missing or invalid credential never opens a stream.
 *
 * <p>When no identity provider is configured the validator is absent and every subscription fails
 * closed with {@code 401}, matching the management endpoints (NFR-029).
 *
 * <p>Anchors: FEAT-008, FEAT-009, NFR-029, C-002.
 */
public final class InspectorSubscriptionAuthorizer {

    private static final Logger logger = LoggerFactory.getLogger(InspectorSubscriptionAuthorizer.class);

    /** The four console roles, any one of which may subscribe to the read-only stream (C-002). */
    private static final Set<String> CONSOLE_ROLES = Set.of("admin", "operator", "auditor", "viewer");

    private static final String MISSING_CREDENTIALS = "Missing authentication credentials";
    private static final String INVALID_CREDENTIALS = "Invalid or missing credentials";

    private final OidcTokenValidator validator;

    public InspectorSubscriptionAuthorizer(OidcTokenValidator validator) {
        this.validator = validator;
    }

    /** Binds this authorizer to the endpoint's authorization seam. */
    public TrafficStreamHandler.StreamAuthorizer asStreamAuthorizer() {
        return this::authorize;
    }

    private TrafficStreamHandler.StreamAuthorizer.AuthResult authorize(
            String bearerToken,
            String cookieHeader
    ) {
        if (validator == null) {
            return TrafficStreamHandler.StreamAuthorizer.AuthResult
                    .unauthenticated("Authentication is unavailable");
        }

        String token = bearerToken != null && !bearerToken.isBlank()
                ? bearerToken.trim()
                : tokenFromCookies(cookieHeader);
        if (token == null || token.isBlank()) {
            return TrafficStreamHandler.StreamAuthorizer.AuthResult.unauthenticated(MISSING_CREDENTIALS);
        }

        OidcValidationResult result = validator.validate(token);
        if (!result.valid()) {
            // The validator's reason can describe key material; it stays in the log, never the body.
            logger.debug("Live traffic stream token rejected: {}", result.errorMessage());
            return TrafficStreamHandler.StreamAuthorizer.AuthResult.unauthenticated(INVALID_CREDENTIALS);
        }

        for (String role : result.roles()) {
            if (role != null && CONSOLE_ROLES.contains(role.toLowerCase(Locale.ROOT))) {
                return TrafficStreamHandler.StreamAuthorizer.AuthResult.allow();
            }
        }
        return TrafficStreamHandler.StreamAuthorizer.AuthResult
                .forbidden("Insufficient permissions for this operation");
    }

    /**
     * Returns the first cookie value shaped like a JWT. The console session cookie holds the operator
     * credential issued at login; its name is the console's, so every cookie is a candidate and only
     * a value the validator accepts authorizes the subscription.
     */
    private static String tokenFromCookies(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        for (String pair : cookieHeader.split(";")) {
            int separator = pair.indexOf('=');
            if (separator <= 0) {
                continue;
            }
            String value = unquote(pair.substring(separator + 1).trim());
            if (looksLikeJwt(value)) {
                return value;
            }
        }
        return null;
    }

    private static String unquote(String value) {
        return value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")
                ? value.substring(1, value.length() - 1)
                : value;
    }

    private static boolean looksLikeJwt(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        int dots = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                dots++;
            }
        }
        return dots == 2;
    }
}
