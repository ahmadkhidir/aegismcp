package dev.aegismcp.gateway.config;

import dev.aegismcp.gateway.identity.JwksKeyResolver;
import dev.aegismcp.gateway.identity.OidcTokenValidator;
import dev.aegismcp.gateway.identity.TestJwtGenerator;
import dev.aegismcp.gateway.killswitch.EmergencyManagementHandler;
import dev.aegismcp.gateway.policy.PolicyManagementHandler;
import io.netty.handler.codec.http.HttpMethod;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the contract-bound role mapping the management endpoints use. A token is only
 * accepted when its signature verifies and it carries a role the endpoint's contract lists;
 * unauthenticated and unauthorized outcomes stay distinct.
 *
 * <p>Anchors: FEAT-008, FEAT-009, NFR-029, C-003, C-005, C-006, C-008, C-009, C-011, C-013,
 * C-014, C-015, C-017, C-018, C-019, C-020.
 */
class VerifiedManagementAuthorizersTest {

    private static final String ISSUER = "https://idp.example.com";
    private static final String AUDIENCE = "aegis-console";
    private static final String KID = "test-key";
    private static final String POLICIES_PATH = PolicyManagementHandler.POLICIES_PATH;
    private static final String SIMULATE_PATH = PolicyManagementHandler.POLICIES_SIMULATE_PATH;

    private static KeyPair keyPair;
    private static VerifiedManagementAuthorizers authorizers;

    @BeforeAll
    static void setUp() throws Exception {
        keyPair = TestJwtGenerator.generateRsaKeyPair();
        JwksKeyResolver resolver = new JwksKeyResolver();
        resolver.registerKey(KID, "RS256", keyPair.getPublic());
        OidcTokenValidator validator = new OidcTokenValidator(resolver, ISSUER, AUDIENCE);
        authorizers = new VerifiedManagementAuthorizers(validator);
    }

    private static String token(String... roles) throws Exception {
        Instant now = Instant.now();
        return "Bearer " + TestJwtGenerator.buildJwt(
                KID, "RS256", keyPair.getPrivate(), ISSUER, AUDIENCE,
                "operator@example.com", now, now.minus(1, ChronoUnit.MINUTES),
                now.plus(5, ChronoUnit.MINUTES), List.of(roles));
    }

    @Test
    @DisplayName("A missing token is unauthenticated on every management surface")
    void missingTokenIsUnauthenticatedEverywhere() {
        assertFalse(authorizers.policy().check(POLICIES_PATH, HttpMethod.GET, null).authorized());
        assertFalse(authorizers.auditRecords().check(null).authorized());
        assertFalse(authorizers.auditVerification().check(null).authorized());
        assertFalse(authorizers.compliance().check(null).authorized());
        assertFalse(authorizers.approvals().check("/api/v1/approvals", HttpMethod.GET, null).authorized());
        assertFalse(authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, null, null)
                .authorized());
    }

    @Test
    @DisplayName("A token with no recognized role is authenticated but forbidden")
    void rolelessTokenIsForbidden() throws Exception {
        String bearer = token("guest");
        var result = authorizers.auditRecords().check(bearer);
        assertFalse(result.authorized());
        assertTrue(result.forbidden());
    }

    @Test
    @DisplayName("The admin role reaches every management surface")
    void adminReachesEverySurface() throws Exception {
        String bearer = token("admin");
        assertTrue(authorizers.policy().check(POLICIES_PATH, HttpMethod.GET, bearer).authorized());
        assertTrue(authorizers.policy().check(POLICIES_PATH, HttpMethod.POST, bearer).authorized());
        assertTrue(authorizers.policy().check(SIMULATE_PATH, HttpMethod.POST, bearer).authorized());
        assertTrue(authorizers.auditRecords().check(bearer).authorized());
        assertTrue(authorizers.auditVerification().check(bearer).authorized());
        assertTrue(authorizers.compliance().check(bearer).authorized());
        assertTrue(authorizers.approvals().check("/api/v1/approvals/pending", HttpMethod.GET, bearer).authorized());
        assertTrue(authorizers.approvals().check("/api/v1/approvals", HttpMethod.GET, bearer).authorized());
        assertTrue(authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, bearer, null)
                .authorized());
        assertTrue(authorizers.emergency().check("/api/v1/metrics/summary", HttpMethod.GET, bearer, null)
                .authorized());
    }

    @Test
    @DisplayName("The operator role handles approvals and emergency actions but not audit or policy writes")
    void operatorRoleBoundary() throws Exception {
        String bearer = token("operator");
        assertTrue(authorizers.approvals().check("/api/v1/approvals/pending", HttpMethod.GET, bearer).authorized());
        assertTrue(authorizers.approvals().check("/api/v1/approvals/appr_1/approve", HttpMethod.POST, bearer)
                .authorized());
        assertTrue(authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, bearer, null)
                .authorized());
        assertTrue(authorizers.policy().check(POLICIES_PATH, HttpMethod.GET, bearer).authorized());

        // C-012 simulation is an operator surface, unlike the C-006 publish path it shares POST with.
        assertTrue(authorizers.policy().check(SIMULATE_PATH, HttpMethod.POST, bearer).authorized());
        assertFalse(authorizers.policy().check(POLICIES_PATH, HttpMethod.POST, bearer).authorized());
        assertFalse(authorizers.policy().check(POLICIES_PATH, HttpMethod.PUT, bearer).authorized());
        assertFalse(authorizers.auditRecords().check(bearer).authorized());
        assertFalse(authorizers.compliance().check(bearer).authorized());
    }

    @Test
    @DisplayName("The auditor role reads the history, not the pending queue or decisions")
    void auditorRoleBoundary() throws Exception {
        String bearer = token("auditor");

        // C-019 history accepts the auditor; C-003 pending and C-004/C-014 decisions do not.
        assertTrue(authorizers.approvals().check("/api/v1/approvals", HttpMethod.GET, bearer).authorized());
        assertFalse(authorizers.approvals().check("/api/v1/approvals/pending", HttpMethod.GET, bearer)
                .authorized());
        assertFalse(authorizers.approvals().check("/api/v1/approvals/appr_1/reject", HttpMethod.POST, bearer)
                .authorized());

        // C-005/C-017 policy reads accept the auditor; C-006/C-018 writes require admin, and
        // C-012 simulation is closed to the auditor.
        assertTrue(authorizers.policy().check(POLICIES_PATH, HttpMethod.GET, bearer).authorized());
        assertFalse(authorizers.policy().check(POLICIES_PATH, HttpMethod.PUT, bearer).authorized());
        assertFalse(authorizers.policy().check(SIMULATE_PATH, HttpMethod.POST, bearer).authorized());

        assertTrue(authorizers.auditRecords().check(bearer).authorized());
        assertTrue(authorizers.auditVerification().check(bearer).authorized());
        assertTrue(authorizers.compliance().check(bearer).authorized());
        assertFalse(authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, bearer, null)
                .authorized());
    }

    @Test
    @DisplayName("The viewer role reads fleet telemetry only")
    void viewerRoleBoundary() throws Exception {
        String bearer = token("viewer");
        assertTrue(authorizers.emergency().check("/api/v1/system/status", HttpMethod.GET, bearer, null)
                .authorized());
        assertTrue(authorizers.emergency().check("/api/v1/metrics/summary", HttpMethod.GET, bearer, null)
                .authorized());
        assertTrue(authorizers.emergency().check("/api/v1/metrics/timeseries", HttpMethod.GET, bearer, null)
                .authorized());
        assertFalse(authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, bearer, null)
                .authorized());
        assertFalse(authorizers.policy().check(POLICIES_PATH, HttpMethod.GET, bearer).authorized());
        assertFalse(authorizers.policy().check(SIMULATE_PATH, HttpMethod.POST, bearer).authorized());
        assertFalse(authorizers.auditRecords().check(bearer).authorized());
    }

    @Test
    @DisplayName("An expired or foreign-issuer token is unauthenticated, never authorized")
    void invalidTokensAreUnauthenticated() throws Exception {
        Instant now = Instant.now();
        String expired = "Bearer " + TestJwtGenerator.buildJwt(
                KID, "RS256", keyPair.getPrivate(), ISSUER, AUDIENCE,
                "operator@example.com", now.minus(10, ChronoUnit.MINUTES), null,
                now.minus(5, ChronoUnit.MINUTES), List.of("admin"));
        var expiredResult = authorizers.auditRecords().check(expired);
        assertFalse(expiredResult.authorized());
        assertFalse(expiredResult.forbidden());

        String wrongIssuer = "Bearer " + TestJwtGenerator.buildJwt(
                KID, "RS256", keyPair.getPrivate(), "https://evil.example.com", AUDIENCE,
                "operator@example.com", now, null, now.plus(5, ChronoUnit.MINUTES), List.of("admin"));
        var wrongIssuerResult = authorizers.auditRecords().check(wrongIssuer);
        assertFalse(wrongIssuerResult.authorized());
        assertFalse(wrongIssuerResult.forbidden());
    }

    @Test
    @DisplayName("The emergency authorizer carries the verified subject and claims for the MFA gate")
    void emergencyCarriesVerifiedClaims() throws Exception {
        Instant now = Instant.now();
        String bearer = "Bearer " + TestJwtGenerator.buildJwt(
                KID, "RS256", keyPair.getPrivate(), ISSUER, AUDIENCE,
                "marcus.vance@example.com", now, null, now.plus(5, ChronoUnit.MINUTES), List.of("admin"));

        EmergencyManagementHandler.EmergencyAuthorizer.AuthResult result =
                authorizers.emergency().check("/api/v1/emergency/kill", HttpMethod.POST, bearer, null);

        assertTrue(result.authorized());
        assertEquals("marcus.vance@example.com", result.subject());
        // The generated token carries no auth_time/amr claims, so a global lockdown fails closed.
        assertFalse(EmergencyManagementHandler.hasFreshMultiFactor(result.claims()));
    }
}
