package dev.aegismcp.gateway.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;

/**
 * Validates X.509 SVID (SPIFFE Verifiable Identity Document) certificate chains presented in mTLS or headers.
 * Extracts and verifies SPIFFE IDs conforming to the SPIFFE X.509 SVID specification.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public class SpiffeSvidValidator {

    private static final Logger logger = LoggerFactory.getLogger(SpiffeSvidValidator.class);
    private static final int SAN_URI_TYPE = 6;

    private final Set<String> allowedTrustDomains;
    private final Set<X509Certificate> trustedRoots;
    private final Clock clock;
    private final CertificateFactory certificateFactory;

    public SpiffeSvidValidator() {
        this(Collections.emptySet(), Collections.emptySet(), Clock.systemUTC());
    }

    public SpiffeSvidValidator(Set<String> allowedTrustDomains) {
        this(allowedTrustDomains, Collections.emptySet(), Clock.systemUTC());
    }

    public SpiffeSvidValidator(Set<String> allowedTrustDomains, Set<X509Certificate> trustedRoots) {
        this(allowedTrustDomains, trustedRoots, Clock.systemUTC());
    }

    public SpiffeSvidValidator(Set<String> allowedTrustDomains, Set<X509Certificate> trustedRoots, Clock clock) {
        this.allowedTrustDomains = allowedTrustDomains != null ?
                allowedTrustDomains.stream().map(String::toLowerCase).collect(java.util.stream.Collectors.toUnmodifiableSet()) :
                Collections.emptySet();
        this.trustedRoots = trustedRoots != null ? Set.copyOf(trustedRoots) : Collections.emptySet();
        this.clock = clock != null ? clock : Clock.systemUTC();
        try {
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to initialize X.509 CertificateFactory", e);
        }
    }

    /**
     * Validates an X.509 certificate presented during mTLS or extracted from a transport layer.
     */
    public SpiffeValidationResult validate(X509Certificate certificate) {
        if (certificate == null) {
            return SpiffeValidationResult.failure("Certificate is null");
        }
        return validate(new X509Certificate[]{certificate});
    }

    /**
     * Validates an X.509 certificate chain.
     */
    public SpiffeValidationResult validate(X509Certificate[] chain) {
        if (chain == null || chain.length == 0 || chain[0] == null) {
            return SpiffeValidationResult.failure("Certificate chain is missing or empty");
        }

        X509Certificate leaf = chain[0];

        // 1. Check validity dates against current clock
        Date now = Date.from(clock.instant());
        try {
            leaf.checkValidity(now);
        } catch (CertificateExpiredException e) {
            logger.warn("SPIFFE SVID certificate expired: {}", e.getMessage());
            return SpiffeValidationResult.failure("SPIFFE SVID certificate is expired");
        } catch (CertificateNotYetValidException e) {
            logger.warn("SPIFFE SVID certificate not yet valid: {}", e.getMessage());
            return SpiffeValidationResult.failure("SPIFFE SVID certificate is not yet valid");
        }

        // 2. Extract and validate SPIFFE ID from SAN URIs
        SpiffeId spiffeId;
        try {
            spiffeId = extractSpiffeId(leaf);
        } catch (IllegalArgumentException e) {
            logger.warn("Failed extracting SPIFFE ID from certificate SAN: {}", e.getMessage());
            return SpiffeValidationResult.failure(e.getMessage());
        }

        // 3. Validate trust domain if restricted
        if (!allowedTrustDomains.isEmpty() && !allowedTrustDomains.contains(spiffeId.trustDomain())) {
            logger.warn("SPIFFE ID trust domain '{}' is not in allowed trust domains: {}",
                    spiffeId.trustDomain(), allowedTrustDomains);
            return SpiffeValidationResult.failure("Untrusted SPIFFE trust domain: " + spiffeId.trustDomain());
        }

        // 4. Validate certificate chain against trusted roots if configured
        if (!trustedRoots.isEmpty()) {
            try {
                validateChainAgainstRoots(chain);
            } catch (GeneralSecurityException e) {
                logger.warn("SPIFFE SVID certificate chain validation failed: {}", e.getMessage());
                return SpiffeValidationResult.failure("Untrusted certificate chain: " + e.getMessage());
            }
        }

        return SpiffeValidationResult.success(spiffeId, spiffeId.workloadId(), leaf);
    }

    /**
     * Validates PEM-encoded certificate chain (e.g. from header or secret).
     */
    public SpiffeValidationResult validatePem(String pemChain) {
        if (pemChain == null || pemChain.isBlank()) {
            return SpiffeValidationResult.failure("PEM certificate string is blank");
        }

        try (InputStream is = new ByteArrayInputStream(pemChain.getBytes(StandardCharsets.UTF_8))) {
            Collection<? extends Certificate> certs = certificateFactory.generateCertificates(is);
            if (certs.isEmpty()) {
                return SpiffeValidationResult.failure("No valid X.509 certificates found in PEM payload");
            }
            X509Certificate[] chain = certs.toArray(new X509Certificate[0]);
            return validate(chain);
        } catch (Exception e) {
            logger.warn("Failed parsing PEM certificate: {}", e.getMessage());
            return SpiffeValidationResult.failure("Failed parsing PEM certificate: " + e.getMessage());
        }
    }

    /**
     * Validates a raw SPIFFE ID string against trust domain rules.
     */
    public SpiffeValidationResult validateSpiffeIdString(String spiffeIdString) {
        if (spiffeIdString == null || spiffeIdString.isBlank()) {
            return SpiffeValidationResult.failure("SPIFFE ID string is blank");
        }
        SpiffeId spiffeId;
        try {
            spiffeId = SpiffeId.parse(spiffeIdString);
        } catch (IllegalArgumentException e) {
            return SpiffeValidationResult.failure(e.getMessage());
        }

        if (!allowedTrustDomains.isEmpty() && !allowedTrustDomains.contains(spiffeId.trustDomain())) {
            return SpiffeValidationResult.failure("Untrusted SPIFFE trust domain: " + spiffeId.trustDomain());
        }

        return SpiffeValidationResult.success(spiffeId, spiffeId.workloadId(), null);
    }

    /**
     * Extracts the SPIFFE ID from the X.509 Subject Alternative Name (SAN) extension.
     * Per SPIFFE X.509 SVID spec, an SVID must contain exactly one SPIFFE ID URI in SAN.
     */
    public SpiffeId extractSpiffeId(X509Certificate certificate) {
        Collection<List<?>> sans;
        try {
            sans = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            throw new IllegalArgumentException("Failed to parse Subject Alternative Names from certificate", e);
        }

        if (sans == null || sans.isEmpty()) {
            throw new IllegalArgumentException("Certificate does not contain Subject Alternative Names extension");
        }

        List<SpiffeId> spiffeIds = new ArrayList<>();
        for (List<?> entry : sans) {
            if (entry != null && entry.size() >= 2 && Integer.valueOf(SAN_URI_TYPE).equals(entry.get(0))) {
                String uriStr = String.valueOf(entry.get(1));
                if (uriStr != null && uriStr.startsWith(SpiffeId.SCHEME + "://")) {
                    spiffeIds.add(SpiffeId.parse(uriStr));
                }
            }
        }

        if (spiffeIds.isEmpty()) {
            throw new IllegalArgumentException("Certificate does not contain a SPIFFE ID URI in SAN extension");
        }

        // SPIFFE X.509 specification requires exactly one SPIFFE ID
        SpiffeId primary = spiffeIds.get(0);
        for (int i = 1; i < spiffeIds.size(); i++) {
            if (!primary.equals(spiffeIds.get(i))) {
                throw new IllegalArgumentException("Certificate contains multiple conflicting SPIFFE IDs in SAN extension");
            }
        }

        return primary;
    }

    /**
     * Extracts the workload identifier from a SPIFFE ID or certificate.
     */
    public String extractWorkloadId(String spiffeIdString) {
        return SpiffeId.parse(spiffeIdString).workloadId();
    }

    public String extractWorkloadId(X509Certificate certificate) {
        return extractSpiffeId(certificate).workloadId();
    }

    public Set<String> allowedTrustDomains() {
        return allowedTrustDomains;
    }

    private void validateChainAgainstRoots(X509Certificate[] chain) throws GeneralSecurityException {
        // Build PKIX parameters with trust anchors
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        for (X509Certificate root : trustedRoots) {
            trustAnchors.add(new TrustAnchor(root, null));
        }

        // If the leaf is self-signed and in trusted roots, verify directly
        if (chain.length == 1) {
            X509Certificate leaf = chain[0];
            for (X509Certificate root : trustedRoots) {
                if (leaf.equals(root)) {
                    leaf.verify(root.getPublicKey());
                    return;
                }
            }
        }

        CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(chain));
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false); // SVID short-lived certificates typically rely on short TTL
        params.setDate(Date.from(clock.instant()));

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(certPath, params);
    }
}
