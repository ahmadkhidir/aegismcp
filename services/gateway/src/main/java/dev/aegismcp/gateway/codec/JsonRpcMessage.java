package dev.aegismcp.gateway.codec;

/**
 * Top-level contract for JSON-RPC 2.0 messages.
 * Anchors: FEAT-001, C-001.
 */
public sealed interface JsonRpcMessage permits JsonRpcRequest, JsonRpcResponse {
    String JSONRPC_VERSION = "2.0";

    String jsonrpc();

    JsonRpcId id();
}
