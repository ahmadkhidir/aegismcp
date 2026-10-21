package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Anomaly rule detecting forbidden tool-chaining transitions.
 * Matches when a sensitive/source tool invocation is followed within a time window
 * by an unauthorized or dangerous sink/target tool invocation.
 * Anchors: FEAT-004, NFR-003.
 */
public class ForbiddenTransitionRule implements AnomalyRule {

    private final String name;
    private final Set<String> sourceTools;
    private final Set<String> targetTools;
    private final List<Pattern> sourcePatterns;
    private final List<Pattern> targetPatterns;
    private final Duration transitionWindow;
    private final String severity;
    private final String violationDescription;

    public ForbiddenTransitionRule(
            String name,
            Set<String> sourceTools,
            Set<String> targetTools,
            Duration transitionWindow,
            String severity,
            String violationDescription
    ) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.sourceTools = normalizeSet(sourceTools);
        this.targetTools = normalizeSet(targetTools);
        this.sourcePatterns = compilePatterns(this.sourceTools);
        this.targetPatterns = compilePatterns(this.targetTools);
        this.transitionWindow = Objects.requireNonNull(transitionWindow, "transitionWindow must not be null");
        this.severity = severity != null ? severity : SecurityViolation.SEVERITY_CRITICAL;
        this.violationDescription = violationDescription;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Optional<AnomalyDetection> evaluate(
            String agentId,
            String currentTool,
            JsonNode currentArguments,
            List<ToolInvocation> history,
            Instant now
    ) {
        if (currentTool == null || !matchesTarget(currentTool)) {
            return Optional.empty();
        }

        Instant cutoff = now.minus(transitionWindow);

        // Find the most recent matching source tool within the transition window
        for (int i = history.size() - 1; i >= 0; i--) {
            ToolInvocation prior = history.get(i);
            if (prior.timestamp().isBefore(cutoff)) {
                // Beyond window limit
                continue;
            }

            if (matchesSource(prior.toolName())) {
                String reason = violationDescription != null
                        ? violationDescription + ": [" + prior.toolName() + "] -> [" + currentTool + "]"
                        : "Forbidden tool transition detected: [" + prior.toolName()
                        + "] followed by egress/action tool [" + currentTool
                        + "] within " + transitionWindow.toSeconds() + "s";

                return Optional.of(new AnomalyDetection(
                        name,
                        reason,
                        severity,
                        List.of(prior.toolName(), currentTool)
                ));
            }
        }

        return Optional.empty();
    }

    private boolean matchesSource(String toolName) {
        if (toolName == null) {
            return false;
        }
        String lower = toolName.toLowerCase(Locale.ROOT);
        if (sourceTools.contains(lower)) {
            return true;
        }
        for (Pattern p : sourcePatterns) {
            if (p.matcher(lower).matches()) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesTarget(String toolName) {
        if (toolName == null) {
            return false;
        }
        String lower = toolName.toLowerCase(Locale.ROOT);
        if (targetTools.contains(lower)) {
            return true;
        }
        for (Pattern p : targetPatterns) {
            if (p.matcher(lower).matches()) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> normalizeSet(Set<String> set) {
        if (set == null) {
            return Collections.emptySet();
        }
        Set<String> normalized = new HashSet<>();
        for (String s : set) {
            if (s != null && !s.isBlank()) {
                normalized.add(s.trim().toLowerCase(Locale.ROOT));
            }
        }
        return Collections.unmodifiableSet(normalized);
    }

    private static List<Pattern> compilePatterns(Set<String> tools) {
        return tools.stream()
                .filter(t -> t.contains("*") || t.contains("?"))
                .map(t -> {
                    String regex = "^" + Pattern.quote(t).replace("*", "\\E.*\\Q").replace("?", "\\E.\\Q") + "$";
                    return Pattern.compile(regex);
                })
                .toList();
    }

    /**
     * Standard rule detecting private data read / filesystem / DB query followed by network egress exfiltration.
     */
    public static ForbiddenTransitionRule dataExfiltrationRule() {
        return dataExfiltrationRule(Duration.ofSeconds(60));
    }

    public static ForbiddenTransitionRule dataExfiltrationRule(Duration window) {
        Set<String> readTools = Set.of(
                "read_file", "filesystem:read", "database_query", "read_resource",
                "db_read", "cat_file", "get_secret", "sql_query", "read_document",
                "s3_get_object", "fetch_internal_data", "file_read"
        );
        Set<String> egressTools = Set.of(
                "external_http", "curl:exec", "fetch:post", "send_email",
                "curl", "http_post", "webhook_send", "upload_file",
                "smtp_send", "http_request", "s3_put_object", "dns_lookup",
                "network:egress", "post_data"
        );
        return new ForbiddenTransitionRule(
                "DataExfiltrationTransitionRule",
                readTools,
                egressTools,
                window,
                SecurityViolation.SEVERITY_CRITICAL,
                "Prohibited data exfiltration tool-chaining sequence"
        );
    }

    /**
     * Standard rule detecting untrusted payload download followed by shell or process execution.
     */
    public static ForbiddenTransitionRule untrustedExecutionRule() {
        return untrustedExecutionRule(Duration.ofSeconds(60));
    }

    public static ForbiddenTransitionRule untrustedExecutionRule(Duration window) {
        Set<String> ingressTools = Set.of(
                "download_file", "fetch_url", "http_get", "curl_get", "wget", "file_download"
        );
        Set<String> execTools = Set.of(
                "shell_exec", "bash", "run_command", "exec", "cmd_exec", "eval", "system_exec"
        );
        return new ForbiddenTransitionRule(
                "UntrustedCodeExecutionRule",
                ingressTools,
                execTools,
                window,
                SecurityViolation.SEVERITY_CRITICAL,
                "Prohibited untrusted download followed by command execution sequence"
        );
    }
}
