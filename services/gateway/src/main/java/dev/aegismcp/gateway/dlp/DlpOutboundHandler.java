package dev.aegismcp.gateway.dlp;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Netty outbound handler that intercepts HTTP and JSON-RPC responses, scanning and redacting
 * sensitive credentials, API keys, private keys, database URLs, and PII before transmission.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
@ChannelHandler.Sharable
public class DlpOutboundHandler extends ChannelOutboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(DlpOutboundHandler.class);

    private final DlpScrubber scrubber;

    public DlpOutboundHandler() {
        this(DlpScrubber.getInstance());
    }

    public DlpOutboundHandler(DlpScrubber scrubber) {
        this.scrubber = Objects.requireNonNull(scrubber, "scrubber must not be null");
    }

    public DlpScrubber getScrubber() {
        return scrubber;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof FullHttpResponse httpResponse) {
            try {
                CharSequence contentType = httpResponse.headers().get(HttpHeaderNames.CONTENT_TYPE);
                if (shouldScrub(contentType)) {
                    FullHttpResponse scrubbedResponse = scrubber.scrubHttpResponse(httpResponse, ctx.alloc());
                    super.write(ctx, scrubbedResponse, promise);
                    return;
                }
            } catch (Exception e) {
                logger.error("Error occurred while redacting outbound HTTP response", e);
            }
        }

        super.write(ctx, msg, promise);
    }

    private boolean shouldScrub(CharSequence contentType) {
        if (contentType == null) {
            return true;
        }
        String ct = contentType.toString().toLowerCase();
        return ct.contains("application/json") || ct.contains("text/") || ct.contains("application/xml");
    }
}
