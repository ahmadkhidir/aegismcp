package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcRequest;

import java.util.concurrent.CompletableFuture;

/**
 * Contract for non-blocking tool call interception and policy verification.
 * Anchors: FEAT-001, C-001.
 */
@FunctionalInterface
public interface ToolCallInterceptor {

    CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request);

    static ToolCallInterceptor allowAll() {
        return (context, request) -> CompletableFuture.completedFuture(InterceptionVerdict.allow());
    }

    /**
     * Chains multiple interceptors sequentially; execution stops on the first Block verdict.
     */
    static ToolCallInterceptor chain(ToolCallInterceptor... interceptors) {
        return (context, request) -> {
            CompletableFuture<InterceptionVerdict> future = CompletableFuture.completedFuture(InterceptionVerdict.allow());
            for (ToolCallInterceptor interceptor : interceptors) {
                future = future.thenCompose(verdict -> {
                    if (verdict instanceof InterceptionVerdict.Block) {
                        return CompletableFuture.completedFuture(verdict);
                    }
                    JsonRpcRequest reqToUse = verdict instanceof InterceptionVerdict.Modify m
                            ? m.modifiedRequest()
                            : request;
                    return interceptor.intercept(context, reqToUse);
                });
            }
            return future;
        };
    }
}
