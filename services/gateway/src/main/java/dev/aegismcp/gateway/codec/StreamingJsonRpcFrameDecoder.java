package dev.aegismcp.gateway.codec;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Line-delimited streaming JSON-RPC frame decoder for Stdio, raw sockets, or SSE streaming connections.
 * Anchors: FEAT-001, C-001.
 */
public class StreamingJsonRpcFrameDecoder extends ByteToMessageDecoder {

    private static final Logger logger = LoggerFactory.getLogger(StreamingJsonRpcFrameDecoder.class);
    private static final int DEFAULT_MAX_FRAME_LENGTH = 16 * 1024 * 1024; // 16MB

    private final JsonRpcCodec codec;
    private final int maxFrameLength;

    public StreamingJsonRpcFrameDecoder() {
        this(JsonRpcCodec.getInstance(), DEFAULT_MAX_FRAME_LENGTH);
    }

    public StreamingJsonRpcFrameDecoder(JsonRpcCodec codec, int maxFrameLength) {
        this.codec = codec;
        this.maxFrameLength = maxFrameLength;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        int eolIndex = findEndOfLine(in);
        if (eolIndex >= 0) {
            int length = eolIndex - in.readerIndex();
            if (length > maxFrameLength) {
                in.readerIndex(eolIndex + 1);
                throw new JsonRpcCodecException(JsonRpcError.invalidRequest("Frame length exceeds limit: " + maxFrameLength));
            }

            ByteBuf frame = in.readSlice(length);
            // Skip the newline characters
            if (in.isReadable() && in.getByte(in.readerIndex()) == '\r') {
                in.skipBytes(1);
            }
            if (in.isReadable() && in.getByte(in.readerIndex()) == '\n') {
                in.skipBytes(1);
            }

            if (frame.isReadable()) {
                byte[] bytes = new byte[frame.readableBytes()];
                frame.readBytes(bytes);
                String line = new String(bytes, StandardCharsets.UTF_8).trim();
                if (!line.isEmpty()) {
                    try {
                        JsonRpcRequest request = codec.decodeRequest(bytes);
                        out.add(request);
                    } catch (JsonRpcCodecException e) {
                        logger.debug("Failed decoding streaming JSON-RPC request frame: {}", e.getMessage());
                        out.add(e);
                    }
                }
            }
        }
    }

    private static int findEndOfLine(ByteBuf buffer) {
        int n = buffer.writerIndex();
        for (int i = buffer.readerIndex(); i < n; i++) {
            byte b = buffer.getByte(i);
            if (b == '\n') {
                return i;
            } else if (b == '\r') {
                return i;
            }
        }
        return -1;
    }
}
