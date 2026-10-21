package dev.aegismcp.gateway.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Resolves and caches public keys (RSA / EC) from JSON Web Key Sets (JWKS).
 * Implements in-memory key caching with grace-period tolerance during IdP key rotation or unreachable endpoints.
 * Anchors: FEAT-009, NFR-020.
 */
public class JwksKeyResolver {

    private static final Logger logger = LoggerFactory.getLogger(JwksKeyResolver.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Clock clock;
    private final Duration cacheTtl;
    private final Duration gracePeriod;
    private final Supplier<String> jwksSupplier;
    private final Map<String, CachedKey> keyCache = new ConcurrentHashMap<>();

    private record CachedKey(
            String kid,
            String kty,
            String alg,
            PublicKey publicKey,
            Instant fetchedAt,
            Instant expiresAt
    ) {
        boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }

        boolean isWithinGracePeriod(Instant now, Duration gracePeriod) {
            return now.isBefore(expiresAt.plus(gracePeriod));
        }
    }

    public JwksKeyResolver() {
        this(null, Duration.ofHours(1), Duration.ofHours(24), Clock.systemUTC());
    }

    public JwksKeyResolver(Supplier<String> jwksSupplier) {
        this(jwksSupplier, Duration.ofHours(1), Duration.ofHours(24), Clock.systemUTC());
    }

    public JwksKeyResolver(Supplier<String> jwksSupplier, Duration cacheTtl, Duration gracePeriod, Clock clock) {
        this.jwksSupplier = jwksSupplier;
        this.cacheTtl = cacheTtl != null ? cacheTtl : Duration.ofHours(1);
        this.gracePeriod = gracePeriod != null ? gracePeriod : Duration.ofHours(24);
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Resolves a public key by Key ID (kid) and optional expected algorithm.
     * Checks cache first; if missing or expired, triggers key refresh.
     * In case of IdP failure, allows keys within the grace period.
     */
    public PublicKey resolveKey(String kid, String alg) {
        Instant now = clock.instant();

        CachedKey cached = kid != null ? keyCache.get(kid) : (keyCache.size() == 1 ? keyCache.values().iterator().next() : null);

        // If key exists and is not expired, return immediately
        if (cached != null && !cached.isExpired(now)) {
            return cached.publicKey();
        }

        // Attempt refresh from JWKS supplier if available
        if (jwksSupplier != null) {
            try {
                refreshKeys();
                CachedKey refreshed = kid != null ? keyCache.get(kid) : null;
                if (refreshed != null && !refreshed.isExpired(now)) {
                    return refreshed.publicKey();
                }
            } catch (Exception e) {
                logger.warn("IdP JWKS endpoint unreachable or failed during key resolution: {}", e.getMessage());
                // Grace period: if cached key is expired but within grace period, use it
                if (cached != null && cached.isWithinGracePeriod(now, gracePeriod)) {
                    logger.warn("Serving cached public key '{}' within grace period until IdP restores", kid);
                    return cached.publicKey();
                }
                throw new AuthenticationException("Identity provider JWKS endpoint unreachable and no valid key in grace period", e);
            }
        }

        // If cached key exists within grace period
        if (cached != null && cached.isWithinGracePeriod(now, gracePeriod)) {
            logger.warn("Serving expired cached public key '{}' within grace period", kid);
            return cached.publicKey();
        }

        return null;
    }

    /**
     * Registers a single public key directly into the cache (for testing or static key injection).
     */
    public void registerKey(String kid, String alg, PublicKey publicKey) {
        Instant now = clock.instant();
        keyCache.put(kid, new CachedKey(kid, publicKey.getAlgorithm(), alg, publicKey, now, now.plus(cacheTtl)));
    }

    /**
     * Parses and registers all keys from a JWKS JSON string.
     */
    public void registerJwksJson(String jwksJson) {
        if (jwksJson == null || jwksJson.isBlank()) {
            return;
        }

        Instant now = clock.instant();
        try {
            JsonNode root = MAPPER.readTree(jwksJson);
            JsonNode keys = root.has("keys") ? root.get("keys") : root;
            if (keys.isArray()) {
                for (JsonNode keyNode : keys) {
                    parseAndStoreJwk(keyNode, now);
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWKS JSON", e);
        }
    }

    /**
     * Refreshes keys by invoking the supplier and parsing returned JWKS JSON.
     */
    public synchronized void refreshKeys() {
        if (jwksSupplier == null) {
            return;
        }
        String jwksJson = jwksSupplier.get();
        registerJwksJson(jwksJson);
    }

    private void parseAndStoreJwk(JsonNode jwk, Instant now) throws Exception {
        String kty = jwk.path("kty").asText();
        String kid = jwk.path("kid").asText(null);
        String alg = jwk.path("alg").asText(null);

        PublicKey publicKey;
        if ("RSA".equalsIgnoreCase(kty)) {
            String nStr = jwk.path("n").asText();
            String eStr = jwk.path("e").asText();
            byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
            byte[] eBytes = Base64.getUrlDecoder().decode(eStr);

            BigInteger modulus = new BigInteger(1, nBytes);
            BigInteger exponent = new BigInteger(1, eBytes);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
        } else if ("EC".equalsIgnoreCase(kty)) {
            String crv = jwk.path("crv").asText();
            String xStr = jwk.path("x").asText();
            String yStr = jwk.path("y").asText();
            byte[] xBytes = Base64.getUrlDecoder().decode(xStr);
            byte[] yBytes = Base64.getUrlDecoder().decode(yStr);

            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = new BigInteger(1, yBytes);
            ECPoint point = new ECPoint(x, y);

            String curveStdName = switch (crv) {
                case "P-256", "secp256r1" -> "secp256r1";
                case "P-384", "secp384r1" -> "secp384r1";
                case "P-521", "secp521r1" -> "secp521r1";
                default -> throw new IllegalArgumentException("Unsupported EC curve: " + crv);
            };

            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curveStdName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

            ECPublicKeySpec spec = new ECPublicKeySpec(point, ecSpec);
            publicKey = KeyFactory.getInstance("EC").generatePublic(spec);
        } else {
            logger.debug("Skipping unsupported JWK key type: {}", kty);
            return;
        }

        String effectiveKid = kid != null ? kid : "default";
        keyCache.put(effectiveKid, new CachedKey(effectiveKid, kty, alg, publicKey, now, now.plus(cacheTtl)));
    }
}
