package dev.aegismcp.gateway.codec;

import io.netty.handler.codec.http.HttpResponseStatus;

import java.util.Objects;

/**
 * Exception raised during JSON-RPC protocol parsing or validation.
 * Anchors: FEAT-001, C-001.
 */
public class JsonRpcCodecException extends RuntimeException {

    private final JsonRpcId id;
    private final JsonRpcError error;

    public JsonRpcCodecException(JsonRpcId id, JsonRpcError error) {
        super(error != null ? error.message() : "JSON-RPC error");
        this.id = id != null ? id : JsonRpcId.nullId();
        this.error = Objects.requireNonNull(error, "error must not be null");
    }

    public JsonRpcCodecException(JsonRpcError error) {
        this(JsonRpcId.nullId(), error);
    }

    public JsonRpcId getId() {
        return id;
    }

    public JsonRpcError getError() {
        return error;
    }

    public HttpResponseStatus getHttpStatus() {
        return error.toHttpStatus();
    }
}
