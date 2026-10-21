package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;

import java.util.Objects;

/**
 * Result of a tool call security interception evaluation.
 * Anchors: FEAT-001, C-001.
 */
public sealed interface InterceptionVerdict permits InterceptionVerdict.Allow, InterceptionVerdict.Block, InterceptionVerdict.Modify {

    static InterceptionVerdict allow() {
        return Allow.INSTANCE;
    }

    static InterceptionVerdict block(JsonRpcError error) {
        return new Block(error);
    }

    static InterceptionVerdict modify(JsonRpcRequest modifiedRequest) {
        return new Modify(modifiedRequest);
    }

    enum Allow implements InterceptionVerdict {
        INSTANCE
    }

    record Block(JsonRpcError error) implements InterceptionVerdict {
        public Block {
            Objects.requireNonNull(error, "error must not be null");
        }
    }

    record Modify(JsonRpcRequest modifiedRequest) implements InterceptionVerdict {
        public Modify {
            Objects.requireNonNull(modifiedRequest, "modifiedRequest must not be null");
        }
    }
}
