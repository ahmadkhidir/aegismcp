package dev.aegismcp.gateway;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Foundational Netty and Loom Virtual Thread gateway server for AegisMCP.
 * Anchors: FEAT-001, NFR-001, NFR-002.
 */
public class AegisGatewayServer {

    private static final Logger logger = LoggerFactory.getLogger(AegisGatewayServer.class);

    public static final String DEFAULT_HOST = "0.0.0.0";
    public static final int DEFAULT_PORT = 8443;
    public static final int MAX_CONTENT_LENGTH = 16 * 1024 * 1024; // 16 MB

    private final String host;
    private final int port;
    private final ExecutorService virtualThreadExecutor;
    private final boolean ownsExecutor;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;
    private volatile boolean running = false;
    private int boundPort = -1;

    public AegisGatewayServer() {
        this(DEFAULT_HOST, DEFAULT_PORT);
    }

    public AegisGatewayServer(String host, int port) {
        this(host, port, Executors.newVirtualThreadPerTaskExecutor(), true);
    }

    public AegisGatewayServer(String host, int port, ExecutorService virtualThreadExecutor) {
        this(host, port, virtualThreadExecutor, false);
    }

    private AegisGatewayServer(String host, int port, ExecutorService virtualThreadExecutor, boolean ownsExecutor) {
        this.host = Objects.requireNonNull(host, "host must not be null");
        this.port = port;
        this.virtualThreadExecutor = Objects.requireNonNull(virtualThreadExecutor, "virtualThreadExecutor must not be null");
        this.ownsExecutor = ownsExecutor;
    }

    /**
     * Starts the Netty server and binds to the configured host and port.
     */
    public synchronized void start() throws InterruptedException {
        if (running) {
            logger.warn("AegisGatewayServer is already running on {}:{}", host, boundPort);
            return;
        }

        bossGroup = new NioEventLoopGroup(1, Thread.ofPlatform().name("netty-boss-", 0).factory());
        workerGroup = new NioEventLoopGroup(0, Thread.ofPlatform().name("netty-worker-", 0).factory());

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 1024)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("http-codec", new HttpServerCodec());
                        ch.pipeline().addLast("http-aggregator", new HttpObjectAggregator(MAX_CONTENT_LENGTH));
                        ch.pipeline().addLast("gateway-dispatcher", new GatewayDispatcherHandler(virtualThreadExecutor));
                    }
                });

        ChannelFuture future = bootstrap.bind(host, port).sync();
        serverChannel = future.channel();
        InetSocketAddress localAddress = (InetSocketAddress) serverChannel.localAddress();
        boundPort = localAddress.getPort();
        running = true;

        logger.info("AegisGatewayServer started successfully on {}:{}", host, boundPort);
    }

    /**
     * Gracefully stops the Netty server and releases resources.
     */
    public synchronized void stop() {
        if (!running) {
            return;
        }

        logger.info("Stopping AegisGatewayServer on {}:{}...", host, boundPort);

        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close().syncUninterruptibly();
            }
        } catch (Exception e) {
            logger.warn("Error closing server channel", e);
        }

        if (bossGroup != null) {
            bossGroup.shutdownGracefully(100, 1000, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully(100, 1000, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }

        if (ownsExecutor) {
            virtualThreadExecutor.shutdown();
            try {
                if (!virtualThreadExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    virtualThreadExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                virtualThreadExecutor.shutdownNow();
            }
        }

        running = false;
        logger.info("AegisGatewayServer stopped cleanly.");
    }

    public boolean isRunning() {
        return running;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return running ? boundPort : port;
    }

    public Channel getServerChannel() {
        return serverChannel;
    }

    public ExecutorService getVirtualThreadExecutor() {
        return virtualThreadExecutor;
    }

    /**
     * Dispatcher handler that offloads request execution to Loom virtual threads.
     */
    public static class GatewayDispatcherHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        private final ExecutorService executor;

        public GatewayDispatcherHandler(ExecutorService executor) {
            this.executor = executor;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            request.retain();
            executor.submit(() -> {
                try {
                    String uri = request.uri();
                    if ("/health".equals(uri) || "/healthz".equals(uri)) {
                        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                                HttpVersion.HTTP_1_1,
                                HttpResponseStatus.OK,
                                ctx.alloc().buffer().writeBytes("{\"status\":\"UP\"}".getBytes())
                        );
                        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                        ctx.writeAndFlush(response);
                        return;
                    }

                    // Default response for unmatched endpoints before Phase 1 C-001 handler attachment
                    DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1,
                            HttpResponseStatus.OK,
                            ctx.alloc().buffer().writeBytes("{\"service\":\"aegis-gateway\"}".getBytes())
                    );
                    response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                    response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
                    ctx.writeAndFlush(response);
                } finally {
                    request.release();
                }
            });
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.error("Channel error caught in pipeline", cause);
            ctx.close();
        }
    }

    public static void main(String[] args) {
        String host = System.getenv().getOrDefault("AEGIS_GATEWAY_HOST", DEFAULT_HOST);
        int port = DEFAULT_PORT;
        String portEnv = System.getenv("AEGIS_GATEWAY_PORT");
        if (portEnv != null) {
            try {
                port = Integer.parseInt(portEnv);
            } catch (NumberFormatException e) {
                logger.warn("Invalid AEGIS_GATEWAY_PORT '{}', using default {}", portEnv, DEFAULT_PORT);
            }
        }

        AegisGatewayServer server = new AegisGatewayServer(host, port);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered, stopping gateway...");
            server.stop();
        }, "gateway-shutdown-hook"));

        try {
            server.start();
            if (server.getServerChannel() != null) {
                server.getServerChannel().closeFuture().sync();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.info("Server interrupted, exiting.");
        } finally {
            server.stop();
        }
    }
}
