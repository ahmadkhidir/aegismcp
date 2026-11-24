package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;

import java.util.Objects;

/**
 * Result of a tool call security interception evaluation.
 *
 * <p>A verdict that resolved through Human-in-the-Loop approval carries the verified reviewer
 * subject, so the terminal audit record can seal who authorized or refused the interaction. A
 * verdict produced automatically, and every verdict that needed no approval, carries {@code null}.
 *
 * <p>Anchors: FEAT-001, FEAT-006, C-001, C-004, C-014.
 */
public sealed interface InterceptionVerdict permits InterceptionVerdict.Allow, InterceptionVerdict.Block, InterceptionVerdict.Modify {

    static InterceptionVerdict allow() {
        return allow(null);
    }

    /** An allow verdict, attributed to the reviewer who approved a suspended call when one did. */
    static InterceptionVerdict allow(String reviewedBy) {
        return new Allow(reviewedBy);
    }

    static InterceptionVerdict block(JsonRpcError error) {
        return block(error, null);
    }

    /** A block verdict, attributed to the reviewer who refused a suspended call when one did. */
    static InterceptionVerdict block(JsonRpcError error, String reviewedBy) {
        return new Block(error, reviewedBy);
    }

    static InterceptionVerdict modify(JsonRpcRequest modifiedRequest) {
        return new Modify(modifiedRequest);
    }

    /** Verified reviewer subject that resolved a required approval, or {@code null}. */
    default String reviewedBy() {
        return null;
    }

    record Allow(String reviewedBy) implements InterceptionVerdict {
    }

    record Block(JsonRpcError error, String reviewedBy) implements InterceptionVerdict {
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
