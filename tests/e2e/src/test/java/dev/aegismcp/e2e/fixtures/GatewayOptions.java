package dev.aegismcp.e2e.fixtures;

import java.time.Duration;

/**
 * Deployment surface the artifact harness configures. Every value maps to an environment variable
 * the packaged gateway documents; the harness never reaches into the process to change state.
 */
public final class GatewayOptions {

    /** Policy covering every tool the conformance suites exercise through the public API. */
    public static final String DEFAULT_POLICY = """
            id: pol_e2e_contracts
            name: E2E Contract Policy
            version: 1.0.0
            targetAgents:
              - "*"
            rules:
              - id: rule_echo
                tool: echo
                action: allow
              - id: rule_ping
                tool: ping
                action: allow
              - id: rule_read_file
                tool: read_file
                action: allow
              - id: rule_curl
                tool: curl:exec
                action: allow
              - id: rule_sensitive
                tool: get_sensitive_config
                action: allow
              - id: rule_typed
                tool: typed_tool
                action: allow
              - id: rule_constrained
                tool: constrained_tool
                action: allow
                constraints:
                  - argument: max_rows
                    operator: lte
                    value: 10
              - id: rule_deploy
                tool: deploy_prod
                action: require_approval
              - id: rule_forbidden
                tool: forbidden_tool
                action: deny
            """;

    public int velocityThreshold = 1_000;
    public int velocityWindowSeconds = 10;
    public Duration approvalTtl = Duration.ofMinutes(5);
    public String policyYaml = DEFAULT_POLICY;
    public boolean slackConfigured = true;
    public boolean upstreamConfigured = true;
    public boolean policyConfigured = true;
    public boolean tlsEnabled = true;
    /** Explicit probe-only node: no serving settings, /health and /ready only. */
    public boolean probeOnly = false;

    public static GatewayOptions defaults() {
        return new GatewayOptions();
    }

    public GatewayOptions velocityThreshold(int value) {
        this.velocityThreshold = value;
        return this;
    }

    public GatewayOptions approvalTtl(Duration value) {
        this.approvalTtl = value;
        return this;
    }

    public GatewayOptions policyYaml(String value) {
        this.policyYaml = value;
        return this;
    }

    public GatewayOptions slackConfigured(boolean value) {
        this.slackConfigured = value;
        return this;
    }

    public GatewayOptions upstreamConfigured(boolean value) {
        this.upstreamConfigured = value;
        return this;
    }

    public GatewayOptions policyConfigured(boolean value) {
        this.policyConfigured = value;
        return this;
    }

    public GatewayOptions tlsEnabled(boolean value) {
        this.tlsEnabled = value;
        return this;
    }

    public GatewayOptions probeOnly(boolean value) {
        this.probeOnly = value;
        return this;
    }
}
