package dev.aegismcp.gateway.identity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.*;

/**
 * Validates OAuth 2.0 / OpenID Connect Bearer JWTs for AI agent workloads.
 * Verifies JWT signature against configured JWKS, validates standard claims (iss, aud, nbf, exp)
 * with a 60-second clock skew tolerance window, and extracts agent roles and subject identity.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public class OidcTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(OidcTokenValidator.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

    private final JwksKeyResolver keyResolver;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final Duration clockSkew;
    private final Clock clock;

    public OidcTokenValidator(JwksKeyResolver keyResolver) {
        this(keyResolver, null, null, DEFAULT_CLOCK_SKEW, Clock.systemUTC());
    }

    public OidcTokenValidator(JwksKeyResolver keyResolver, String expectedIssuer, String expectedAudience) {
        this(keyResolver, expectedIssuer, expectedAudience, DEFAULT_CLOCK_SKEW, Clock.systemUTC());
    }

    public OidcTokenValidator(
            JwksKeyResolver keyResolver,
            String expectedIssuer,
            String expectedAudience,
            Duration clockSkew,
            Clock clock
    ) {
        this.keyResolver = keyResolver != null ? keyResolver : new JwksKeyResolver();
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.clockSkew = clockSkew != null ? clockSkew : DEFAULT_CLOCK_SKEW;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Validates an OpenID Connect Bearer token.
     *
     * @param bearerToken Raw JWT token string (without 'Bearer ' prefix)
     * @return OidcValidationResult with claims and roles or error message
     */
    public OidcValidationResult validate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return OidcValidationResult.failure("Bearer token is missing or empty");
        }

        String token = bearerToken.trim();
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = token.substring(7).trim();
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return OidcValidationResult.failure("Malformed JWT: expected 3 dot-delimited segments, got " + parts.length);
        }

        // 1. Decode header
        JsonNode headerNode;
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            headerNode = MAPPER.readTree(headerBytes);
        } catch (Exception e) {
            return OidcValidationResult.failure("Malformed JWT header: " + e.getMessage());
        }

        String alg = headerNode.path("alg").asText(null);
        if (alg == null || "none".equalsIgnoreCase(alg)) {
            return OidcValidationResult.failure("Unsecured or missing JWT algorithm (alg=none is rejected)");
        }

        String jcaAlgorithm = mapJcaAlgorithm(alg);
        if (jcaAlgorithm == null) {
            return OidcValidationResult.failure("Unsupported JWT algorithm: " + alg);
        }

        String kid = headerNode.has("kid") ? headerNode.get("kid").asText() : null;

        // 2. Decode payload & parse claims
        Map<String, Object> claims;
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            claims = MAPPER.readValue(payloadBytes, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            return OidcValidationResult.failure("Malformed JWT payload claims: " + e.getMessage());
        }

        // 3. Validate issuer
        if (expectedIssuer != null && !expectedIssuer.isBlank()) {
            Object iss = claims.get("iss");
            if (iss == null || !expectedIssuer.equals(String.valueOf(iss))) {
                return OidcValidationResult.failure("Invalid JWT issuer: expected '" + expectedIssuer + "', got '" + iss + "'");
            }
        }

        // 4. Validate audience
        if (expectedAudience != null && !expectedAudience.isBlank()) {
            Object aud = claims.get("aud");
            if (!matchesAudience(aud, expectedAudience)) {
                return OidcValidationResult.failure("Invalid JWT audience: expected '" + expectedAudience + "', got '" + aud + "'");
            }
        }

        // 5. Validate exp and nbf with clock skew tolerance
        long nowSeconds = clock.instant().getEpochSecond();
        long skewSeconds = clockSkew.toSeconds();

        if (claims.containsKey("exp")) {
            long expSeconds = toLongSeconds(claims.get("exp"));
            if (nowSeconds > expSeconds + skewSeconds) {
                return OidcValidationResult.failure("JWT token is expired (exp=" + expSeconds + ", now=" + nowSeconds + ", skew=" + skewSeconds + "s)");
            }
        }

        if (claims.containsKey("nbf")) {
            long nbfSeconds = toLongSeconds(claims.get("nbf"));
            if (nowSeconds < nbfSeconds - skewSeconds) {
                return OidcValidationResult.failure("JWT token is not yet valid (nbf=" + nbfSeconds + ", now=" + nowSeconds + ", skew=" + skewSeconds + "s)");
            }
        }

        // 6. Verify signature against resolved JWKS public key
        PublicKey publicKey;
        try {
            publicKey = keyResolver.resolveKey(kid, alg);
        } catch (AuthenticationException e) {
            return OidcValidationResult.failure("IdP error during key lookup: " + e.getMessage());
        } catch (Exception e) {
            return OidcValidationResult.failure("Failed resolving public key from JWKS: " + e.getMessage());
        }

        if (publicKey == null) {
            return OidcValidationResult.failure("No public key found in JWKS for kid: " + (kid != null ? kid : "default"));
        }

        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
            byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);

            byte[] effectiveSig = alg.startsWith("ES") ? formatEcdsaSignature(signatureBytes, alg) : signatureBytes;

            Signature verifier = Signature.getInstance(jcaAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(signingInput);

            if (!verifier.verify(effectiveSig)) {
                return OidcValidationResult.failure("Invalid cryptographic JWT signature");
            }
        } catch (Exception e) {
            logger.warn("JWT cryptographic verification failed: {}", e.getMessage());
            return OidcValidationResult.failure("JWT signature verification failed: " + e.getMessage());
        }

        // 7. Extract subject and roles
        String subject = String.valueOf(claims.getOrDefault("sub", "unknown-agent"));
        Set<String> roles = extractRoles(claims);

        return OidcValidationResult.success(subject, claims, roles);
    }

    private static boolean matchesAudience(Object aud, String expectedAudience) {
        if (aud == null) return false;
        if (aud instanceof String s) {
            return expectedAudience.equals(s);
        }
        if (aud instanceof Collection<?> list) {
            for (Object item : list) {
                if (expectedAudience.equals(String.valueOf(item))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static long toLongSeconds(Object val) {
        if (val instanceof Number n) {
            return n.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(val));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = new LinkedHashSet<>();

        // Check 'roles' claim
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof Collection<?> list) {
            for (Object item : list) {
                roles.add(String.valueOf(item).trim());
            }
        } else if (rolesObj instanceof String s) {
            for (String r : s.split(",")) {
                if (!r.isBlank()) roles.add(r.trim());
            }
        }

        // Check single 'role' claim
        Object roleObj = claims.get("role");
        if (roleObj instanceof String s && !s.isBlank()) {
            roles.add(s.trim());
        }

        // Check 'groups' claim
        Object groupsObj = claims.get("groups");
        if (groupsObj instanceof Collection<?> list) {
            for (Object item : list) {
                roles.add(String.valueOf(item).trim());
            }
        }

        // Check 'scope' claim (OAuth 2.0 scopes e.g. "read write admin")
        Object scopeObj = claims.get("scope");
        if (scopeObj instanceof String s) {
            for (String sc : s.split("\\s+")) {
                if (!sc.isBlank()) roles.add(sc.trim());
            }
        }

        return Collections.unmodifiableSet(roles);
    }

    private static String mapJcaAlgorithm(String alg) {
        return switch (alg.toUpperCase()) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            default -> null;
        };
    }

    /**
     * Converts a raw IEEE P1363 (R || S) ECDSA signature to DER sequence format expected by JCA.
     * If the signature is already DER encoded, returns as-is.
     */
    private static byte[] formatEcdsaSignature(byte[] rawOrDer, String alg) throws IOException {
        if (rawOrDer.length > 2 && rawOrDer[0] == 0x30) {
            return rawOrDer; // Already DER
        }

        int coordLen = switch (alg.toUpperCase()) {
            case "ES256" -> 32;
            case "ES384" -> 48;
            case "ES512" -> 66;
            default -> rawOrDer.length / 2;
        };

        if (rawOrDer.length != coordLen * 2) {
            return rawOrDer;
        }

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rawOrDer, 0, coordLen));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rawOrDer, coordLen, coordLen * 2));

        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        int bodyLen = 2 + rBytes.length + 2 + sBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30); // SEQUENCE
        if (bodyLen < 128) {
            out.write(bodyLen);
        } else {
            out.write(0x81);
            out.write(bodyLen);
        }
        out.write(0x02); // INTEGER
        out.write(rBytes.length);
        out.write(rBytes);
        out.write(0x02); // INTEGER
        out.write(sBytes.length);
        out.write(sBytes);

        return out.toByteArray();
    }
}
