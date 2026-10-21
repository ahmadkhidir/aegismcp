package dev.aegismcp.gateway.proxy;

import io.netty.channel.ChannelPipeline;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pipeline helper to attach the MCP proxy handler to an existing Netty ChannelPipeline.
 * Anchors: FEAT-001, C-001.
 */
public final class McpProxyPipelineConfigurator {

    private static final Logger logger = LoggerFactory.getLogger(McpProxyPipelineConfigurator.class);
    public static final String HANDLER_NAME = "mcp-proxy-handler";

    private McpProxyPipelineConfigurator() {
    }

    /**
     * Injects the McpProxyHandler before the dispatcher or at the end of the pipeline.
     */
    public static void configure(ChannelPipeline pipeline, McpProxyHandler proxyHandler) {
        if (pipeline.get("gateway-dispatcher") != null) {
            pipeline.addBefore("gateway-dispatcher", HANDLER_NAME, proxyHandler);
            logger.debug("McpProxyHandler injected before 'gateway-dispatcher'");
        } else {
            pipeline.addLast(HANDLER_NAME, proxyHandler);
            logger.debug("McpProxyHandler added to end of pipeline");
        }
    }
}
