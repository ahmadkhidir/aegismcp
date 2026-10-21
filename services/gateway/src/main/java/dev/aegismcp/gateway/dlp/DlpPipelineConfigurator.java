package dev.aegismcp.gateway.dlp;

import io.netty.channel.ChannelPipeline;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pipeline helper to attach the DLP outbound handler to a Netty ChannelPipeline.
 * Anchors: FEAT-005, C-001.
 */
public final class DlpPipelineConfigurator {

    private static final Logger logger = LoggerFactory.getLogger(DlpPipelineConfigurator.class);
    public static final String HANDLER_NAME = "dlp-outbound-filter";

    private DlpPipelineConfigurator() {
    }

    /**
     * Attaches the DlpOutboundHandler before the http-codec or at the start of outbound handlers.
     */
    public static void configure(ChannelPipeline pipeline, DlpScrubber scrubber) {
        configure(pipeline, new DlpOutboundHandler(scrubber));
    }

    /**
     * Attaches the DlpOutboundHandler before the http-codec.
     */
    public static void configure(ChannelPipeline pipeline, DlpOutboundHandler outboundHandler) {
        if (pipeline.get("http-codec") != null) {
            pipeline.addBefore("http-codec", HANDLER_NAME, outboundHandler);
            logger.debug("DlpOutboundHandler injected before 'http-codec'");
        } else {
            pipeline.addFirst(HANDLER_NAME, outboundHandler);
            logger.debug("DlpOutboundHandler added to beginning of pipeline");
        }
    }
}
