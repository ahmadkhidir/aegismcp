package dev.aegismcp.gateway.identity;

import dev.aegismcp.gateway.killswitch.GatewayMetrics;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the edge binds one live session to one counted agent identity. Anchors: FEAT-009, C-008,
 * C-010.
 */
class IdentityVerificationHandlerTest {

    private static final String SPIFFE_URI = "spiffe://cluster.local/ns/agents/sa/support-bot";
    private static final String WORKLOAD_ID = "ns/agents/sa/support-bot";

    private GatewayMetrics metrics;
    private KillSwitchManager killSwitchManager;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        metrics = new GatewayMetrics();
        killSwitchManager = new KillSwitchManager();
        killSwitchManager.attachMetrics(metrics);
        channel = newChannel();
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    @DisplayName("C-010 / FEAT-009: a SPIFFE session with both identifiers registers one identity key")
    void countsSpiffeSessionOnce() {
        sendAgentRequest(channel);

        // The verified identity carries both a workload ID and the SPIFFE URI it derives from, and
        // both forms resolve to the same live session for kill-switch targeting (C-008).
        assertNotNull(channel.attr(dev.aegismcp.gateway.proxy.AgentIdentity.VERIFIED_ATTRIBUTE).get());
        assertTrue(killSwitchManager.hasAgentSession(WORKLOAD_ID));
        assertTrue(killSwitchManager.hasAgentSession(SPIFFE_URI));
        assertEquals(1, metrics.getActiveAgents());
        assertEquals(1, metrics.getActiveConnections());

        // A second request on the same live channel is still the same agent session.
        sendAgentRequest(channel);
        assertEquals(1, metrics.getActiveAgents());
        assertEquals(1, metrics.getActiveConnections());

        channel.close();
        assertEquals(0, metrics.getActiveAgents());
        assertEquals(0, metrics.getActiveConnections());
    }

    @Test
    @DisplayName("C-010: repeated register and close cycles neither double-count nor leak a count")
    void repeatedRegisterAndCloseCyclesDoNotLeak() {
        for (int cycle = 0; cycle < 3; cycle++) {
            EmbeddedChannel session = newChannel();
            sendAgentRequest(session);
            assertEquals(1, metrics.getActiveAgents(), "cycle " + cycle + " counts the live session once");
            assertEquals(1, metrics.getActiveConnections(), "cycle " + cycle + " counts one live stream");

            sendAgentRequest(session);
            assertEquals(1, metrics.getActiveAgents(), "cycle " + cycle + " does not double-count a repeated register");

            session.close();
            assertEquals(0, metrics.getActiveAgents(), "cycle " + cycle + " releases the agent count");
            assertEquals(0, metrics.getActiveConnections(), "cycle " + cycle + " releases the stream count");
            session.finishAndReleaseAll();
        }
    }

    @Test
    @DisplayName("C-008 / C-010: a SPIFFE agent is addressable by either form and severed once")
    void quarantineByEitherIdentityFormSeversOneSession() {
        sendAgentRequest(channel);
        assertEquals(1, metrics.getActiveAgents());

        assertEquals(1, killSwitchManager.quarantineAgent(SPIFFE_URI, "containment"));

        assertFalse(channel.isOpen());
        assertEquals(0, metrics.getActiveAgents());
        assertEquals(0, metrics.getActiveConnections());
        assertTrue(killSwitchManager.isAgentQuarantined(WORKLOAD_ID));
        assertTrue(killSwitchManager.isAgentQuarantined(SPIFFE_URI));
    }

    private EmbeddedChannel newChannel() {
        return new EmbeddedChannel(new IdentityVerificationHandler(
                spiffeResolver(), null, killSwitchManager, Runnable::run));
    }

    private void sendAgentRequest(EmbeddedChannel target) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/mcp/v1/rpc",
                Unpooled.EMPTY_BUFFER
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, 0);

        target.writeInbound(request);
        target.runPendingTasks();
    }

    private static AgentIdentityResolver spiffeResolver() {
        return new AgentIdentityResolver(null, null, true) {
            @Override
            public AgentIdentity resolve(FullHttpRequest request, ChannelHandlerContext ctx) {
                return AgentIdentity.spiffe(
                        SPIFFE_URI,
                        WORKLOAD_ID,
                        Map.of("spiffe_id", SPIFFE_URI, "workload_id", WORKLOAD_ID),
                        Set.of("ns:agents", "sa:support-bot")
                );
            }
        };
    }
}
