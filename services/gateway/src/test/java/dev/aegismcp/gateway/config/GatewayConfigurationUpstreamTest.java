package dev.aegismcp.gateway.config;

import dev.aegismcp.gateway.proxy.UpstreamTransport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for resolving the upstream transport from operator configuration.
 *
 * <p>Anchors: FEAT-001, C-001.
 */
class GatewayConfigurationUpstreamTest {

    @Test
    @DisplayName("FEAT-001: an explicit transport setting selects the upstream transport")
    void explicitTransportSelectsTransport() {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp",
                "AEGIS_UPSTREAM_TRANSPORT", "sse"));

        assertEquals(UpstreamTransport.SSE, configuration.upstream().transport());
    }

    @Test
    @DisplayName("FEAT-001: a ws endpoint without an explicit setting infers WebSocket")
    void webSocketEndpointIsInferred() {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                "AEGIS_UPSTREAM_URL", "wss://tools.example.test/mcp"));

        assertEquals(UpstreamTransport.WEBSOCKET, configuration.upstream().transport());
    }

    @Test
    @DisplayName("FEAT-001: the default upstream transport is one HTTPS call per request")
    void defaultTransportIsHttp() {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp"));

        assertEquals(UpstreamTransport.HTTP, configuration.upstream().transport());
    }

    @Test
    @DisplayName("FEAT-001: an endpoint whose scheme contradicts the transport fails startup")
    void contradictorySchemeFailsStartup() {
        assertThrows(ConfigurationException.class, () -> GatewayConfiguration.load(Map.of(
                "AEGIS_UPSTREAM_URL", "ws://tools.example.test/mcp",
                "AEGIS_UPSTREAM_TRANSPORT", "http")));
    }

    @Test
    @DisplayName("FEAT-001: an undeclared transport name fails startup")
    void unknownTransportFailsStartup() {
        assertThrows(ConfigurationException.class, () -> GatewayConfiguration.load(Map.of(
                "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp",
                "AEGIS_UPSTREAM_TRANSPORT", "carrier-pigeon")));
    }
}
