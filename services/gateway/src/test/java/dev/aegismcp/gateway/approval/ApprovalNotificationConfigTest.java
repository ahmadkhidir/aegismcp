package dev.aegismcp.gateway.approval;

import dev.aegismcp.gateway.config.ConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that approval notification settings are fail-closed at startup: a half-configured
 * destination fails with the missing key named, and an unconfigured deployment simply has no
 * out-of-band channel while the console queue remains the fallback.
 *
 * <p>Anchors: FEAT-006, NFR-027.
 */
class ApprovalNotificationConfigTest {

    @Test
    @DisplayName("FEAT-006: no destination configured leaves only the console queue")
    void noDestinationIsValid() {
        ApprovalNotificationConfig config = ApprovalNotificationConfig.load(Map.of());

        assertFalse(config.anyConfigured());
        assertFalse(config.slackConfigured());
        assertFalse(config.webhookConfigured());
        assertFalse(config.emailConfigured());
        assertNull(config.consoleBaseUrl());
    }

    @Test
    @DisplayName("FEAT-006: a Slack webhook without the signing secret fails startup naming both keys")
    void slackRequiresWebhookAndSigningSecretTogether() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> ApprovalNotificationConfig.load(Map.of(
                        "AEGIS_SLACK_APPROVAL_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")));

        assertTrue(error.getMessage().contains("AEGIS_SLACK_APPROVAL_WEBHOOK_URL"));
        assertTrue(error.getMessage().contains("AEGIS_SLACK_SIGNING_SECRET"));
    }

    @Test
    @DisplayName("FEAT-006: a configured Slack workspace resolves its webhook, secret, and operator map")
    void slackConfigurationResolves() {
        String signingSecret = TestCredentials.signingSecret();
        ApprovalNotificationConfig config = ApprovalNotificationConfig.load(Map.of(
                "AEGIS_SLACK_APPROVAL_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X",
                "AEGIS_SLACK_SIGNING_SECRET", signingSecret,
                "AEGIS_SLACK_OPERATORS",
                "[{\"slackUserId\":\"U1\",\"operator\":\"elena@example.com\",\"roles\":[\"operator\"]},"
                        + "{\"slackUserId\":\"U2\",\"operator\":\"auditor@example.com\",\"roles\":[\"viewer\"]}]"));

        assertTrue(config.slackConfigured());
        assertNotNull(config.slack());
        assertEquals("https://hooks.slack.com/services/T/B/X", config.slack().webhookUrl().toString());
        assertEquals(signingSecret, config.slack().signingSecret());

        SlackOperatorRegistry.SlackOperator elena = config.slack().operators().find("U1").orElseThrow();
        assertEquals("elena@example.com", elena.operator());
        assertTrue(elena.canDecide());

        SlackOperatorRegistry.SlackOperator auditor = config.slack().operators().find("U2").orElseThrow();
        assertFalse(auditor.canDecide(), "A mapped operator without operator/admin is refused");
        assertTrue(config.slack().operators().find("U3").isEmpty(), "An unmapped Slack user is not trusted");
    }

    @Test
    @DisplayName("FEAT-006: a malformed operator map fails startup instead of dropping a mapping")
    void malformedOperatorMapFailsStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> SlackOperatorRegistry.parse("[{\"operator\":\"no-id@example.com\"}]",
                        "AEGIS_SLACK_OPERATORS"));
        assertTrue(error.getMessage().contains("AEGIS_SLACK_OPERATORS"));
    }

    @Test
    @DisplayName("FEAT-006: an incomplete email destination fails startup naming the missing keys")
    void incompleteEmailConfigurationFailsStartup() {
        ConfigurationException error = assertThrows(ConfigurationException.class,
                () -> ApprovalNotificationConfig.load(Map.of(
                        "AEGIS_APPROVAL_EMAIL_SMTP_HOST", "smtp.example.com")));

        assertTrue(error.getMessage().contains("AEGIS_APPROVAL_EMAIL_FROM"));
        assertTrue(error.getMessage().contains("AEGIS_APPROVAL_EMAIL_TO"));
    }

    @Test
    @DisplayName("FEAT-006: an email destination defaults to STARTTLS on port 587")
    void emailConfigurationDefaults() {
        ApprovalNotificationConfig config = ApprovalNotificationConfig.load(Map.of(
                "AEGIS_APPROVAL_EMAIL_SMTP_HOST", "smtp.example.com",
                "AEGIS_APPROVAL_EMAIL_FROM", "approvals@example.com",
                "AEGIS_APPROVAL_EMAIL_TO", "alice@example.com, bob@example.com"));

        assertTrue(config.emailConfigured());
        assertEquals(587, config.email().smtpPort());
        assertTrue(config.email().startTls());
        assertEquals(2, config.email().recipients().size());
    }

    @Test
    @DisplayName("FEAT-006: a notification URL must be http or https")
    void webhookRequiresHttpScheme() {
        assertThrows(ConfigurationException.class,
                () -> ApprovalNotificationConfig.load(Map.of(
                        "AEGIS_APPROVAL_WEBHOOK_URL", "file:///etc/passwd")));
    }

    @Test
    @DisplayName("FEAT-006: a retry count below one is rejected")
    void retryCountMustBePositive() {
        assertThrows(ConfigurationException.class,
                () -> ApprovalNotificationConfig.load(Map.of(
                        "AEGIS_APPROVAL_NOTIFY_ATTEMPTS", "0")));
    }
}
