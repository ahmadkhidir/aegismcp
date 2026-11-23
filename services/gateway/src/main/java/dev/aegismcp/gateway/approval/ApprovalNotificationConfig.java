package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import dev.aegismcp.gateway.config.ConfigurationException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Out-of-band approval notification settings resolved from the environment and the optional
 * gateway YAML document at startup.
 *
 * <p>Every destination is optional: a deployment that configures none still suspends the call and
 * leaves the ticket reachable from the Web Console queue, which is FEAT-006's fallback when Slack
 * delivery is unavailable. A destination that is present but incomplete fails startup with an
 * error naming the missing key, because a half-configured approval channel would silently drop the
 * notification that a human is waiting on (NFR-027).
 *
 * <p>Anchors: FEAT-006, NFR-027, C-001, C-004.
 */
public record ApprovalNotificationConfig(
        Slack slack,
        URI webhookUrl,
        Email email,
        URI consoleBaseUrl,
        int maxAttempts,
        Duration retryBackoff,
        Duration requestTimeout
) {

    /** The gateway configuration document environment variable, read for YAML-based settings. */
    public static final String CONFIG_FILE_ENV = "AEGIS_GATEWAY_CONFIG";

    public static final int DEFAULT_MAX_ATTEMPTS = 3;
    public static final Duration DEFAULT_RETRY_BACKOFF = Duration.ofMillis(250);
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private static final int DEFAULT_SMTP_PORT = 587;

    public ApprovalNotificationConfig {
        if (maxAttempts < 1) {
            throw new ConfigurationException("AEGIS_APPROVAL_NOTIFY_ATTEMPTS must be at least 1");
        }
        Objects.requireNonNull(retryBackoff, "retryBackoff must not be null");
        if (retryBackoff.isNegative()) {
            throw new ConfigurationException("AEGIS_APPROVAL_NOTIFY_BACKOFF_MS must not be negative");
        }
        Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
        if (requestTimeout.isNegative() || requestTimeout.isZero()) {
            throw new ConfigurationException("AEGIS_APPROVAL_NOTIFY_TIMEOUT_MS must be positive");
        }
    }

    /** A Slack workspace that posts interactive approval messages and receives their callbacks. */
    public record Slack(URI webhookUrl, String signingSecret, SlackOperatorRegistry operators) {
        public Slack {
            Objects.requireNonNull(webhookUrl, "webhookUrl must not be null");
            Objects.requireNonNull(signingSecret, "signingSecret must not be null");
            Objects.requireNonNull(operators, "operators must not be null");
        }
    }

    /**
     * SMTP relay settings for the email approval notification. {@code startTls} defaults to true:
     * credentials are only ever sent after the channel is encrypted.
     */
    public record Email(
            String smtpHost,
            int smtpPort,
            String username,
            String password,
            String from,
            List<String> recipients,
            boolean startTls
    ) {
        public Email {
            if (smtpHost == null || smtpHost.isBlank()) {
                throw new ConfigurationException("AEGIS_APPROVAL_EMAIL_SMTP_HOST must not be blank");
            }
            if (smtpPort < 1 || smtpPort > 65535) {
                throw new ConfigurationException(
                        "AEGIS_APPROVAL_EMAIL_SMTP_PORT must be between 1 and 65535, got " + smtpPort);
            }
            if (from == null || from.isBlank()) {
                throw new ConfigurationException("AEGIS_APPROVAL_EMAIL_FROM must not be blank");
            }
            recipients = recipients != null ? List.copyOf(recipients) : List.of();
            if (recipients.isEmpty()) {
                throw new ConfigurationException("AEGIS_APPROVAL_EMAIL_TO must name at least one recipient");
            }
            if ((username == null) != (password == null)) {
                throw new ConfigurationException(
                        "AEGIS_APPROVAL_EMAIL_SMTP_USERNAME and AEGIS_APPROVAL_EMAIL_SMTP_PASSWORD "
                                + "must be configured together");
            }
        }
    }

    /** A configuration with no destination: tickets stay pending in the console queue (FEAT-006). */
    public static ApprovalNotificationConfig none() {
        return new ApprovalNotificationConfig(null, null, null, null,
                DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_BACKOFF, DEFAULT_REQUEST_TIMEOUT);
    }

    public boolean slackConfigured() {
        return slack != null;
    }

    public boolean webhookConfigured() {
        return webhookUrl != null;
    }

    public boolean emailConfigured() {
        return email != null;
    }

    /** True when at least one out-of-band destination can receive a notification. */
    public boolean anyConfigured() {
        return slackConfigured() || webhookConfigured() || emailConfigured();
    }

    /** Reads the environment, then the YAML document named by {@value #CONFIG_FILE_ENV}. */
    public static ApprovalNotificationConfig load() {
        return load(System.getenv());
    }

    /** Test seam for {@link #load()}: resolves the same rules against a supplied environment. */
    public static ApprovalNotificationConfig load(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        Settings settings = new Settings(environment, readDocument(environment.get(CONFIG_FILE_ENV)));
        return resolve(settings);
    }

    private static ApprovalNotificationConfig resolve(Settings settings) {
        Slack slack = resolveSlack(settings);
        URI webhookUrl = webhookUri("AEGIS_APPROVAL_WEBHOOK_URL",
                settings.text("AEGIS_APPROVAL_WEBHOOK_URL", "approval.webhookUrl"));
        Email email = resolveEmail(settings);
        URI consoleBaseUrl = webhookUri("AEGIS_APPROVAL_CONSOLE_URL",
                settings.text("AEGIS_APPROVAL_CONSOLE_URL", "approval.consoleUrl"));
        if (consoleBaseUrl != null
                && (consoleBaseUrl.getQuery() != null || consoleBaseUrl.getFragment() != null)) {
            // Links are appended to the message body; a base URL with a query or fragment would
            // produce an unusable approval link.
            throw new ConfigurationException(
                    "AEGIS_APPROVAL_CONSOLE_URL must be a base URL without a query or fragment");
        }

        return new ApprovalNotificationConfig(
                slack,
                webhookUrl,
                email,
                consoleBaseUrl,
                settings.integer("AEGIS_APPROVAL_NOTIFY_ATTEMPTS", "approval.notify.attempts",
                        DEFAULT_MAX_ATTEMPTS),
                Duration.ofMillis(settings.integer("AEGIS_APPROVAL_NOTIFY_BACKOFF_MS",
                        "approval.notify.backoffMs", (int) DEFAULT_RETRY_BACKOFF.toMillis())),
                Duration.ofMillis(settings.integer("AEGIS_APPROVAL_NOTIFY_TIMEOUT_MS",
                        "approval.notify.timeoutMs", (int) DEFAULT_REQUEST_TIMEOUT.toMillis()))
        );
    }

    private static Slack resolveSlack(Settings settings) {
        String webhook = settings.text("AEGIS_SLACK_APPROVAL_WEBHOOK_URL",
                "approval.slack.approvalWebhookUrl");
        String signingSecret = settings.text("AEGIS_SLACK_SIGNING_SECRET",
                "approval.slack.signingSecret");
        String operatorsRaw = settings.rawText("AEGIS_SLACK_OPERATORS", "approval.slack.operators");

        if (webhook == null && signingSecret == null) {
            return null;
        }
        if (webhook == null || signingSecret == null) {
            throw new ConfigurationException(
                    "AEGIS_SLACK_APPROVAL_WEBHOOK_URL and AEGIS_SLACK_SIGNING_SECRET must be "
                            + "configured together; a Slack callback cannot be authenticated without "
                            + "the signing secret and no message can be posted without the webhook URL");
        }

        SlackOperatorRegistry operators = SlackOperatorRegistry.parse(
                operatorsRaw, "AEGIS_SLACK_OPERATORS");
        return new Slack(webhookUri("AEGIS_SLACK_APPROVAL_WEBHOOK_URL", webhook), signingSecret,
                operators);
    }

    private static Email resolveEmail(Settings settings) {
        String host = settings.text("AEGIS_APPROVAL_EMAIL_SMTP_HOST", "approval.email.smtpHost");
        String from = settings.text("AEGIS_APPROVAL_EMAIL_FROM", "approval.email.from");
        List<String> recipients = settings.csv("AEGIS_APPROVAL_EMAIL_TO", "approval.email.to");
        String username = settings.text("AEGIS_APPROVAL_EMAIL_SMTP_USERNAME",
                "approval.email.smtpUsername");
        String password = settings.text("AEGIS_APPROVAL_EMAIL_SMTP_PASSWORD",
                "approval.email.smtpPassword");

        boolean anyEmailSetting = host != null || from != null || !recipients.isEmpty()
                || username != null || password != null
                || settings.present("AEGIS_APPROVAL_EMAIL_SMTP_PORT", "approval.email.smtpPort");
        if (!anyEmailSetting) {
            return null;
        }
        if (host == null || from == null || recipients.isEmpty()) {
            throw new ConfigurationException(
                    "AEGIS_APPROVAL_EMAIL_SMTP_HOST, AEGIS_APPROVAL_EMAIL_FROM, and "
                            + "AEGIS_APPROVAL_EMAIL_TO must be configured together for email approval "
                            + "notifications");
        }

        int port = settings.integer("AEGIS_APPROVAL_EMAIL_SMTP_PORT", "approval.email.smtpPort",
                DEFAULT_SMTP_PORT);
        boolean startTls = settings.bool("AEGIS_APPROVAL_EMAIL_STARTTLS", "approval.email.startTls",
                true);
        return new Email(host, port, username, password, from, recipients, startTls);
    }

    private static URI webhookUri(String key, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(value.trim());
        } catch (URISyntaxException e) {
            throw new ConfigurationException(key + " is not a valid URI", e);
        }
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new ConfigurationException(
                    key + " must be an http or https URL, got '" + scheme + "'");
        }
        return uri;
    }

    private static JsonNode readDocument(String configFile) {
        if (configFile == null || configFile.isBlank()) {
            return null;
        }
        Path path = Path.of(configFile);
        if (!Files.isReadable(path)) {
            throw new ConfigurationException(CONFIG_FILE_ENV + " is not readable: " + path);
        }
        try {
            return new ObjectMapper(new YAMLFactory()).readTree(path.toFile());
        } catch (IOException e) {
            throw new ConfigurationException(CONFIG_FILE_ENV + " is not valid YAML: " + path, e);
        }
    }

    /** Environment-then-YAML lookup for the approval notification keys. */
    private static final class Settings {
        private final Map<String, String> environment;
        private final JsonNode document;

        private Settings(Map<String, String> environment, JsonNode document) {
            this.environment = environment;
            this.document = document;
        }

        private boolean present(String envKey, String yamlPath) {
            return text(envKey, yamlPath) != null;
        }

        private String text(String envKey, String yamlPath) {
            String fromEnv = environment.get(envKey);
            if (fromEnv != null && !fromEnv.isBlank()) {
                return fromEnv.trim();
            }
            JsonNode node = node(yamlPath);
            if (node != null && node.isValueNode() && !node.asText().isBlank()) {
                return node.asText().trim();
            }
            return null;
        }

        private String rawText(String envKey, String yamlPath) {
            String fromEnv = environment.get(envKey);
            if (fromEnv != null && !fromEnv.isBlank()) {
                return fromEnv.trim();
            }
            JsonNode node = node(yamlPath);
            if (node == null || node.isNull() || node.isMissingNode()) {
                return null;
            }
            return node.isValueNode() ? node.asText() : node.toString();
        }

        private int integer(String envKey, String yamlPath, int fallback) {
            String value = text(envKey, yamlPath);
            if (value == null) {
                return fallback;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new ConfigurationException(envKey + " must be an integer, got '" + value + "'");
            }
        }

        private boolean bool(String envKey, String yamlPath, boolean fallback) {
            String value = text(envKey, yamlPath);
            if (value == null) {
                return fallback;
            }
            if ("true".equalsIgnoreCase(value)) {
                return true;
            }
            if ("false".equalsIgnoreCase(value)) {
                return false;
            }
            throw new ConfigurationException(envKey + " must be true or false, got '" + value + "'");
        }

        private List<String> csv(String envKey, String yamlPath) {
            JsonNode node = node(yamlPath);
            List<String> values = new ArrayList<>();
            if (node != null && node.isArray()) {
                for (JsonNode item : node) {
                    if (item != null && !item.asText().isBlank()) {
                        values.add(item.asText().trim());
                    }
                }
                return List.copyOf(values);
            }
            String fromEnv = environment.get(envKey);
            String raw = fromEnv != null && !fromEnv.isBlank()
                    ? fromEnv
                    : (node != null && node.isValueNode() ? node.asText() : null);
            if (raw != null) {
                for (String part : raw.split(",")) {
                    if (!part.isBlank()) {
                        values.add(part.trim());
                    }
                }
            }
            return List.copyOf(values);
        }

        private JsonNode node(String dottedPath) {
            JsonNode current = document;
            for (String segment : dottedPath.split("\\.")) {
                if (current == null || !current.isObject()) {
                    return null;
                }
                current = current.get(segment);
            }
            return current;
        }
    }
}
