package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Netty proxy pipeline interceptor enforcing declarative tool access policies.
 * Evaluates incoming JSON-RPC tools/call requests against compiled policy ASTs.
 * Integrates directly with the Netty pipeline via {@link ToolCallInterceptor}.
 * Anchors: FEAT-001, FEAT-002, C-001, NFR-001, NFR-027.
 */
public class DeclarativePolicyInterceptor implements ToolCallInterceptor {

    private final PolicyEvaluator evaluator;
    private final ApprovalHandler approvalHandler;

    @FunctionalInterface
    public interface ApprovalHandler {
        CompletableFuture<InterceptionVerdict> handleApproval(SecurityContext context, JsonRpcRequest request, PolicyEvaluationResult result);
    }

    public DeclarativePolicyInterceptor(PolicyEvaluator evaluator) {
        this(evaluator, null);
    }

    public DeclarativePolicyInterceptor(PolicyEvaluator evaluator, ApprovalHandler approvalHandler) {
        this.evaluator = Objects.requireNonNull(evaluator, "evaluator must not be null");
        this.approvalHandler = approvalHandler;
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        // Fast-path for non-tool call invocations (e.g. tools/list, initialize, ping)
        if (!request.isToolCall()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        String toolName = request.toolName();
        JsonNode arguments = request.toolArguments();

        PolicyEvaluationResult result = evaluator.evaluate(context, toolName, arguments);

        if (result.isAllowed()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        if (result.isRequireApproval()) {
            if (approvalHandler != null) {
                return approvalHandler.handleApproval(context, request, result);
            }
            // Suspend or block with approval required policy violation
            return CompletableFuture.completedFuture(
                    InterceptionVerdict.block(JsonRpcError.policyViolation(result.reason()))
            );
        }

        // Policy denial / argument constraint violation (-32001 Policy Violation -> HTTP 403 Forbidden)
        return CompletableFuture.completedFuture(
                InterceptionVerdict.block(JsonRpcError.policyViolation(result.reason()))
        );
    }

    public PolicyEvaluator getEvaluator() {
        return evaluator;
    }
}
