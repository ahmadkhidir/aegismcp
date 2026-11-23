package dev.aegismcp.gateway.config;

import dev.aegismcp.gateway.approval.ApprovalManagementHandler;
import dev.aegismcp.gateway.audit.AuditRecordsHandler;
import dev.aegismcp.gateway.audit.AuditVerificationHandler;
import dev.aegismcp.gateway.compliance.ComplianceExportHandler;
import dev.aegismcp.gateway.identity.OidcTokenValidator;
import dev.aegismcp.gateway.identity.OidcValidationResult;
import dev.aegismcp.gateway.killswitch.EmergencyManagementHandler;
import dev.aegismcp.gateway.policy.PolicyManagementHandler;
import io.netty.handler.codec.http.HttpMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;
import java.util.Set;

/**
 * Authorizers for the management endpoints built from the verified OIDC token the endpoint's
 * contract names. A token is accepted only when its signature, issuer, audience, and expiry verify
 * and it carries one of the roles the contract lists; a missing token is unauthenticated and a
 * verified token without the role is forbidden.
 *
 * <p>This replaces the token-substring checks the endpoint classes carry as their local default.
 * The mapping is contract-bound: C-003/C-004/C-014 (approval decisions) and C-008/C-021 (emergency
 * and release) require {@code admin} or {@code operator}; C-005 requires {@code admin},
 * {@code operator}, or {@code auditor} and C-006 requires {@code admin}; C-007/C-011/C-013/C-015
 * require {@code admin} or {@code auditor}; C-009/C-010 read the fleet with any role.
 *
 * <p>Anchors: FEAT-008, FEAT-009, NFR-029, NFR-027, C-003..C-021.
 */
public final class VerifiedManagementAuthorizers {

    private static final Logger logger = LoggerFactory.getLogger(VerifiedManagementAuthorizers.class);

    private static final Set<String> ANY_ROLE = Set.of("admin", "operator", "auditor", "viewer");
    private static final Set<String> ADMIN_OPERATOR_AUDITOR = Set.of("admin", "operator", "auditor");
    private static final Set<String> ADMIN_OPERATOR = Set.of("admin", "operator");
    private static final Set<String> ADMIN_AUDITOR = Set.of("admin", "auditor");
    private static final Set<String> ADMIN_ONLY = Set.of("admin");

    private final OidcTokenValidator validator;

    public VerifiedManagementAuthorizers(OidcTokenValidator validator) {
        this.validator = validator;
    }

    public PolicyManagementHandler.PolicyAuthorizer policy() {
        return (method, bearerToken) -> {
            Verdict verdict = verify(bearerToken,
                    HttpMethod.POST.equals(method) || HttpMethod.PUT.equals(method) ? ADMIN_ONLY : ADMIN_OPERATOR_AUDITOR);
            return new PolicyManagementHandler.PolicyAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    public AuditVerificationHandler.AuditAuthorizer auditVerification() {
        return bearerToken -> {
            Verdict verdict = verify(bearerToken, ADMIN_AUDITOR);
            return new AuditVerificationHandler.AuditAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    public AuditRecordsHandler.AuditAuthorizer auditRecords() {
        return bearerToken -> {
            Verdict verdict = verify(bearerToken, ADMIN_AUDITOR);
            return new AuditRecordsHandler.AuditAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    public ComplianceExportHandler.ComplianceAuthorizer compliance() {
        return bearerToken -> {
            Verdict verdict = verify(bearerToken, ADMIN_AUDITOR);
            return new ComplianceExportHandler.ComplianceAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    public ApprovalManagementHandler.ApprovalAuthorizer approvals() {
        return (method, bearerToken) -> {
            Verdict verdict = verify(bearerToken, ADMIN_OPERATOR);
            return new ApprovalManagementHandler.ApprovalAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    public EmergencyManagementHandler.EmergencyAuthorizer emergency() {
        return (path, method, bearerToken, cookieHeader) -> {
            Set<String> allowed = EmergencyManagementHandler.PATH_EMERGENCY_KILL.equals(path)
                    ? ADMIN_OPERATOR
                    : ANY_ROLE;
            Verdict verdict = verify(bearerToken, allowed);
            return new EmergencyManagementHandler.EmergencyAuthorizer.AuthResult(
                    verdict.authorized(), verdict.forbidden(), verdict.reason());
        };
    }

    private Verdict verify(String bearerToken, Set<String> allowedRoles) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return new Verdict(false, false, "Missing authentication credentials");
        }
        if (validator == null) {
            return new Verdict(false, false, "Authentication is unavailable");
        }

        OidcValidationResult result = validator.validate(bearerToken);
        if (!result.valid()) {
            // The validator's reason can describe key material; it stays in the log, never the body.
            logger.debug("Management token rejected: {}", result.errorMessage());
            return new Verdict(false, false, "Invalid or missing credentials");
        }

        for (String role : result.roles()) {
            if (allowedRoles.contains(role.toLowerCase(Locale.ROOT))) {
                return new Verdict(true, false, null);
            }
        }
        return new Verdict(false, true, "Insufficient permissions for this operation");
    }

    private record Verdict(boolean authorized, boolean forbidden, String reason) {
    }
}
