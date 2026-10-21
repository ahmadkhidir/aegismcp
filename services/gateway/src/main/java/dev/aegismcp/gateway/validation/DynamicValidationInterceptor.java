package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Netty proxy pipeline interceptor enforcing dynamic parameter validation and injection sanitization.
 * Intercepts tool calls before reaching upstream servers, rejecting invalid requests with JSON-RPC -32005
 * and appending SecurityViolation records to AuditLedger.
 * Anchors: FEAT-012, NFR-024, C-001, schema.md#SecurityViolation.
 */
public class DynamicValidationInterceptor implements ToolCallInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(DynamicValidationInterceptor.class);
    public static final int ERROR_CODE_SCHEMA_PARAMETER_VIOLATION = -32005;

    private final DynamicParameterValidator validator;
    private final AuditLedger auditLedger;
    private final List<SecurityViolation> recordedViolations = Collections.synchronizedList(new ArrayList<>());

    public DynamicValidationInterceptor() {
        this(new DynamicParameterValidator(), null);
    }

    public DynamicValidationInterceptor(DynamicParameterValidator validator) {
        this(validator, null);
    }

    public DynamicValidationInterceptor(DynamicParameterValidator validator, AuditLedger auditLedger) {
        this.validator = Objects.requireNonNull(validator, "validator must not be null");
        this.auditLedger = auditLedger;
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        // Fast-path: non-tool calls bypass parameter validation directly
        if (request == null || !request.isToolCall()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        String agentId = extractAgentId(context);
        String toolName = request.toolName();
        JsonNode arguments = request.toolArguments();

        ValidationResult result = validator.validate(agentId, toolName, arguments);
        if (result.isValid()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        String violationType = result.primaryViolationType();
        String summary = result.summaryMessage();
        logger.warn("Dynamic parameter validation rejected tool invocation: agent='{}', tool='{}', type='{}', details='{}'",
                agentId, toolName, violationType, summary);

        // Record SecurityViolation per schema.md#SecurityViolation
        SecurityViolation violation = SecurityViolation.of(
                agentId,
                violationType,
                SecurityViolation.SEVERITY_HIGH,
                summary
        );
        recordedViolations.add(violation);

        // Record into AuditLedger if configured
        CompletableFuture<Void> auditFuture = CompletableFuture.completedFuture(null);
        if (auditLedger != null) {
            AuditRecord record = AuditRecord.create(
                    agentId,
                    toolName,
                    "BLOCKED",
                    0,
                    0.5,
                    "SecurityViolation: id=" + violation.id() + ", type=" + violation.violationType() + ", details=" + violation.details()
            );
            auditFuture = auditLedger.append(record).thenAccept(r -> {});
        }

        // Fail-closed with JSON-RPC error -32005 Schema/Parameter Violation
        JsonRpcError error = new JsonRpcError(
                ERROR_CODE_SCHEMA_PARAMETER_VIOLATION,
                "Schema/Parameter Violation: " + summary
        );

        return auditFuture.thenApply(v -> InterceptionVerdict.block(error));
    }

    private String extractAgentId(SecurityContext context) {
        if (context != null && context.identity() != null && context.identity().agentId() != null) {
            return context.identity().agentId();
        }
        return "anonymous";
    }

    public DynamicParameterValidator getValidator() {
        return validator;
    }

    public AuditLedger getAuditLedger() {
        return auditLedger;
    }

    public List<SecurityViolation> getRecordedViolations() {
        synchronized (recordedViolations) {
            return new ArrayList<>(recordedViolations);
        }
    }

    public void clearRecordedViolations() {
        recordedViolations.clear();
    }
}
