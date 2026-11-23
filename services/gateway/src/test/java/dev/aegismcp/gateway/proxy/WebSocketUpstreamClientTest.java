package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the WebSocket upstream transport. A local Netty server speaks the WebSocket
 * upgrade and answers one JSON-RPC message per text frame.
 *
 * <p>Anchors: FEAT-001, C-001.
 */
class WebSocketUpstreamClientTest {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final ObjectMapper MAPPER = JsonRpcCodec.getInstance().getMapper();

    private EventLoopGroup group;
    private Channel serverChannel;

    @BeforeEach
    void startServer() throws InterruptedException {
        group = new NioEventLoopGroup(1);
        serverChannel = new ServerBootstrap()
                .group(group)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new HttpServerCodec());
                        ch.pipeline().addLast(new HttpObjectAggregator(64 * 1024));
                        ch.pipeline().addLast(new WebSocketServerProtocolHandler("/ws"));
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<TextWebSocketFrame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, TextWebSocketFrame frame)
                                    throws Exception {
                                JsonNode request = MAPPER.readTree(frame.text());
                                if ("ping".equals(request.path("method").asText())) {
                                    return;
                                }
                                // Send a stray notification first: it must be discarded, not
                                // delivered to a waiting call.
                                ctx.writeAndFlush(new TextWebSocketFrame(
                                        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}"));
                                String body = "{\"jsonrpc\":\"2.0\",\"id\":" + request.get("id")
                                        + ",\"result\":{\"echoed\":true}}";
                                ctx.writeAndFlush(new TextWebSocketFrame(body));
                            }
                        });
                    }
                })
                .bind("127.0.0.1", 0)
                .sync()
                .channel();
    }

    @AfterEach
    void stopServer() {
        if (serverChannel != null) {
            serverChannel.close().syncUninterruptibly();
        }
        if (group != null) {
            group.shutdownGracefully(0, 100, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
    }

    @Test
    @DisplayName("FEAT-001: one text frame per message, pipelined calls answered with their own id")
    void answersPipelinedCallsWithTheirOwnId() throws Exception {
        int port = ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort();
        WebSocketUpstreamClient client = new WebSocketUpstreamClient(
                URI.create("ws://127.0.0.1:" + port + "/ws"), CONNECT_TIMEOUT, REQUEST_TIMEOUT);
        try {
            CompletableFuture<JsonRpcResponse> first = client.forward(context(), toolCall("ws-a"));
            CompletableFuture<JsonRpcResponse> second = client.forward(context(), toolCall("ws-b"));

            JsonRpcResponse firstResponse = first.get(10, TimeUnit.SECONDS);
            JsonRpcResponse secondResponse = second.get(10, TimeUnit.SECONDS);

            assertEquals("ws-a", ((JsonRpcId.StringId) firstResponse.id()).stringValue());
            assertEquals("ws-b", ((JsonRpcId.StringId) secondResponse.id()).stringValue());
            assertEquals(true, firstResponse.result().get("echoed").asBoolean());
            assertEquals(true, secondResponse.result().get("echoed").asBoolean());
        } finally {
            client.close();
        }
    }

    private static SecurityContext context() {
        return SecurityContext.of(AgentIdentity.anonymous(), null);
    }

    private static JsonRpcRequest toolCall(String id) {
        return new JsonRpcRequest(JsonRpcId.of(id), "tools/call", null);
    }
}
