package dev.aegismcp.gateway.config;

import dev.aegismcp.gateway.approval.ApprovalNotificationConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the startup contract: a serving node must carry every setting an agent-facing proxy
 * needs, a probe-only node may omit them, and a partial approval destination fails with the
 * missing key named.
 *
 * <p>Anchors: FEAT-001, FEAT-006, NFR-010, NFR-027.
 */
class GatewayConfigurationStartupTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    @DisplayName("NFR-027: a serving node with no settings fails startup naming every missing key")
    void missingServingSettingsFailStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> GatewayConfiguration.load(Map.of()));

        assertTrue(error.getMessage().contains("AEGIS_TLS_KEYSTORE_PATH"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_UPSTREAM_URL"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_OIDC_JWKS_URL/AEGIS_SPIFFE_TRUST_DOMAINS"),
                error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_POLICY_FILE"), error.getMessage());
        assertTrue(error.getMessage().contains(GatewayConfiguration.PROBE_ONLY_ENV), error.getMessage());
    }

    @Test
    @DisplayName("NFR-027: only the absent settings are named, never a defaulted substitute")
    void partialServingConfigurationNamesOnlyTheMissingKeys() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> GatewayConfiguration.load(Map.of(
                        "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp")));

        assertFalse(error.getMessage().contains("AEGIS_UPSTREAM_URL"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_TLS_KEYSTORE_PATH"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_OIDC_JWKS_URL/AEGIS_SPIFFE_TRUST_DOMAINS"),
                error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_POLICY_FILE"), error.getMessage());
    }

    @Test
    @DisplayName("NFR-027: probe-only mode boots without any serving setting")
    void probeOnlyModeBootsWithoutServingConfiguration() {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                GatewayConfiguration.PROBE_ONLY_ENV, "true"));

        assertTrue(configuration.probeOnly());
        assertFalse(configuration.rpcConfigured());
        assertTrue(configuration.missingServingSettings().isEmpty());
        assertFalse(configuration.tls().servesTraffic());
        assertFalse(configuration.upstream().configured());
        assertFalse(configuration.identity().configured());
    }

    @Test
    @DisplayName("NFR-010: a complete serving configuration loads and is ready to proxy")
    void completeServingConfigurationLoads() throws Exception {
        Path keystore = Files.writeString(temporaryDirectory.resolve("gateway.p12"), "keystore");
        Path policy = Files.writeString(temporaryDirectory.resolve("policy.yaml"), "id: pol_test");

        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                "AEGIS_TLS_KEYSTORE_PATH", keystore.toString(),
                "AEGIS_TLS_KEYSTORE_PASSWORD", "changeit",
                "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp",
                "AEGIS_OIDC_JWKS_URL", "https://identity.example.test/jwks",
                "AEGIS_OIDC_ISSUER", "https://identity.example.test",
                "AEGIS_POLICY_FILE", policy.toString()));

        assertFalse(configuration.probeOnly());
        assertTrue(configuration.rpcConfigured());
        assertTrue(configuration.tls().enabled());
        assertFalse(configuration.tls().explicitlyDisabled());
    }

    @Test
    @DisplayName("NFR-027: a plaintext listener is accepted only when explicitly disabled")
    void plaintextListenerIsAcceptedOnlyWhenExplicitlyDisabled() throws Exception {
        Path policy = Files.writeString(temporaryDirectory.resolve("policy.yaml"), "id: pol_test");

        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                "AEGIS_TLS_ENABLED", "false",
                "AEGIS_UPSTREAM_URL", "https://tools.example.test/mcp",
                "AEGIS_OIDC_JWKS_URL", "https://identity.example.test/jwks",
                "AEGIS_OIDC_ISSUER", "https://identity.example.test",
                "AEGIS_POLICY_FILE", policy.toString()));

        assertFalse(configuration.tls().enabled());
        assertTrue(configuration.tls().explicitlyDisabled());
        assertTrue(configuration.rpcConfigured());
    }

    @Test
    @DisplayName("NFR-027: constructing an incomplete serving configuration directly also fails")
    void directConstructionOfIncompleteServingConfigurationFails() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> new GatewayConfiguration(
                        "127.0.0.1", 0, false,
                        GatewayConfiguration.Tls.disabled(),
                        GatewayConfiguration.Upstream.none(),
                        GatewayConfiguration.Identity.none(),
                        null,
                        ApprovalNotificationConfig.none(),
                        Duration.ofSeconds(300),
                        1024,
                        100,
                        Duration.ofSeconds(10)));

        assertTrue(error.getMessage().contains("AEGIS_TLS_KEYSTORE_PATH"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_UPSTREAM_URL"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_OIDC_JWKS_URL/AEGIS_SPIFFE_TRUST_DOMAINS"),
                error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_POLICY_FILE"), error.getMessage());
    }

    @Test
    @DisplayName("FEAT-006: approval destinations resolve through the gateway configuration")
    void approvalDestinationsResolveThroughGatewayConfiguration() {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.ofEntries(
                Map.entry(GatewayConfiguration.PROBE_ONLY_ENV, "true"),
                Map.entry("AEGIS_SLACK_APPROVAL_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X"),
                Map.entry("AEGIS_SLACK_SIGNING_SECRET", "test-signing-secret"),
                Map.entry("AEGIS_SLACK_OPERATORS",
                        "[{\"slackUserId\":\"U1\",\"operator\":\"elena@example.com\",\"roles\":[\"operator\"]}]"),
                Map.entry("AEGIS_APPROVAL_WEBHOOK_URL", "https://hooks.example.test/approvals"),
                Map.entry("AEGIS_APPROVAL_EMAIL_SMTP_HOST", "smtp.example.test"),
                Map.entry("AEGIS_APPROVAL_EMAIL_SMTP_PORT", "2525"),
                Map.entry("AEGIS_APPROVAL_EMAIL_SMTP_USERNAME", "relay@example.test"),
                Map.entry("AEGIS_APPROVAL_EMAIL_SMTP_PASSWORD", "relay-password"),
                Map.entry("AEGIS_APPROVAL_EMAIL_FROM", "approvals@example.test"),
                Map.entry("AEGIS_APPROVAL_EMAIL_TO", "operators@example.test"),
                Map.entry("AEGIS_APPROVAL_CONSOLE_URL", "https://console.example.test"),
                Map.entry("AEGIS_APPROVAL_NOTIFY_ATTEMPTS", "5"),
                Map.entry("AEGIS_APPROVAL_NOTIFY_BACKOFF_MS", "750"),
                Map.entry("AEGIS_APPROVAL_NOTIFY_TIMEOUT_MS", "9000")));

        ApprovalNotificationConfig approvals = configuration.approvals();
        assertTrue(approvals.slackConfigured());
        assertEquals("https://hooks.slack.com/services/T/B/X",
                approvals.slack().webhookUrl().toString());
        assertEquals("test-signing-secret", approvals.slack().signingSecret());
        assertEquals("elena@example.com",
                approvals.slack().operators().find("U1").orElseThrow().operator());
        assertEquals("https://hooks.example.test/approvals", approvals.webhookUrl().toString());
        assertTrue(approvals.emailConfigured());
        assertEquals("smtp.example.test", approvals.email().smtpHost());
        assertEquals(2525, approvals.email().smtpPort());
        assertEquals("relay@example.test", approvals.email().username());
        assertEquals("relay-password", approvals.email().password());
        assertEquals("approvals@example.test", approvals.email().from());
        assertEquals(java.util.List.of("operators@example.test"), approvals.email().recipients());
        assertEquals("https://console.example.test", approvals.consoleBaseUrl().toString());
        assertEquals(5, approvals.maxAttempts());
        assertEquals(Duration.ofMillis(750), approvals.retryBackoff());
        assertEquals(Duration.ofMillis(9000), approvals.requestTimeout());
    }

    @Test
    @DisplayName("FEAT-006: a Slack webhook without its signing secret fails startup naming the key")
    void partialSlackDestinationFailsStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> GatewayConfiguration.load(Map.of(
                        GatewayConfiguration.PROBE_ONLY_ENV, "true",
                        "AEGIS_SLACK_APPROVAL_WEBHOOK_URL",
                        "https://hooks.slack.com/services/T/B/X")));

        assertTrue(error.getMessage().contains("AEGIS_SLACK_APPROVAL_WEBHOOK_URL"),
                error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_SLACK_SIGNING_SECRET"), error.getMessage());
    }

    @Test
    @DisplayName("FEAT-006: an email destination missing its sender or recipients fails startup")
    void partialEmailDestinationFailsStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> GatewayConfiguration.load(Map.of(
                        GatewayConfiguration.PROBE_ONLY_ENV, "true",
                        "AEGIS_APPROVAL_EMAIL_SMTP_HOST", "smtp.example.test")));

        assertTrue(error.getMessage().contains("AEGIS_APPROVAL_EMAIL_SMTP_HOST"),
                error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_APPROVAL_EMAIL_FROM"), error.getMessage());
        assertTrue(error.getMessage().contains("AEGIS_APPROVAL_EMAIL_TO"), error.getMessage());
    }

    @Test
    @DisplayName("NFR-027: an unparseable probe-only flag fails startup instead of guessing")
    void unparseableProbeFlagFailsStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> GatewayConfiguration.load(Map.of(
                        GatewayConfiguration.PROBE_ONLY_ENV, "sometimes")));

        assertTrue(error.getMessage().contains(GatewayConfiguration.PROBE_ONLY_ENV),
                error.getMessage());
    }
}
