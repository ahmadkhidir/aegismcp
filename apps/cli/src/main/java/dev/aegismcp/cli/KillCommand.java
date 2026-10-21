package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Callable;

/**
 * Command line action to invoke the emergency global kill-switch and circuit breaker.
 * Conforms to Contract C-008 (POST /api/v1/emergency/kill).
 * Anchors: FEAT-010, C-008.
 */
@Command(
        name = "kill",
        description = "Trigger emergency kill-switch to quarantine rogue agents or sever compromised MCP connections (C-008)",
        mixinStandardHelpOptions = true
)
public class KillCommand implements Callable<Integer> {

    @Option(names = {"-a", "--agent"}, description = "Target agent identifier to quarantine")
    private String agentId;

    @Option(names = {"--target-type"}, defaultValue = "agent", description = "Target type: agent, global, tool, or server (default: agent)")
    private String targetType;

    @Option(names = {"--target-id"}, description = "Explicit target identifier (alternative to --agent)")
    private String targetId;

    @Option(names = {"-g", "--gateway"}, defaultValue = "http://localhost:8080", description = "AegisMCP Gateway base URL (default: http://localhost:8080)")
    private String gatewayUrl;

    @Option(names = {"-r", "--reason"}, defaultValue = "Emergency kill-switch invoked via aegis-cli", description = "Operational reason for triggering emergency kill-switch")
    private String reason;

    @Option(names = {"-t", "--token"}, description = "Administrator Bearer token for authentication")
    private String token;

    @Option(names = {"--confirm-lockdown"}, defaultValue = "false", description = "Explicit confirmation required when triggering global lockdown")
    private boolean confirmLockdown;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    public KillCommand() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), new ObjectMapper());
    }

    public KillCommand(HttpClient httpClient, ObjectMapper mapper) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
    }

    @Override
    public Integer call() {
        String resolvedTargetType = targetType != null ? targetType.trim().toLowerCase() : "agent";
        String resolvedTargetId = agentId != null && !agentId.isBlank() ? agentId.trim() : targetId;

        if ("global".equals(resolvedTargetType)) {
            if (!confirmLockdown) {
                System.err.println("Error: Global kill-switch lockdown requires explicit '--confirm-lockdown' flag.");
                return 1;
            }
            if (resolvedTargetId == null || resolvedTargetId.isBlank()) {
                resolvedTargetId = "global";
            }
        } else if (resolvedTargetId == null || resolvedTargetId.isBlank()) {
            System.err.println("Error: Target agent identifier is required (use --agent <agent-id>).");
            return 1;
        }

        // Construct C-008 JSON payload
        ObjectNode requestBody = mapper.createObjectNode();
        requestBody.put("targetType", resolvedTargetType);
        requestBody.put("targetId", resolvedTargetId);
        requestBody.put("reason", reason);

        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(requestBody);
        } catch (Exception e) {
            System.err.println("Error: Failed to construct JSON request: " + e.getMessage());
            return 1;
        }

        String targetEndpoint = gatewayUrl.replaceAll("/+$", "") + "/api/v1/emergency/kill";

        try {
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(targetEndpoint))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

            if (token != null && !token.isBlank()) {
                reqBuilder.header("Authorization", "Bearer " + token.trim());
            }

            HttpRequest request = reqBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            int statusCode = response.statusCode();
            String responseBody = response.body();

            if (statusCode == 200) {
                try {
                    JsonNode respNode = mapper.readTree(responseBody);
                    String status = respNode.has("status") ? respNode.get("status").asText() : "EXECUTED";
                    int affectedSessions = respNode.has("affectedSessions") ? respNode.get("affectedSessions").asInt() : 0;
                    String timestamp = respNode.has("timestamp") ? respNode.get("timestamp").asText() : "N/A";

                    System.out.println("✓ Emergency kill-switch invoked successfully (HTTP 200).");
                    System.out.println("  Target:            " + resolvedTargetType + " [" + resolvedTargetId + "]");
                    System.out.println("  Result Status:     " + status);
                    System.out.println("  Affected Sessions: " + affectedSessions);
                    System.out.println("  Timestamp:         " + timestamp);
                    return 0;
                } catch (Exception e) {
                    System.out.println("✓ Emergency kill-switch invoked successfully (HTTP 200).");
                    System.out.println("  Response: " + responseBody);
                    return 0;
                }
            } else if (statusCode == 400) {
                System.err.println("✗ Error: Bad Request (HTTP 400) - Invalid target type or missing target ID.");
                if (responseBody != null && !responseBody.isBlank()) {
                    System.err.println("  Details: " + responseBody);
                }
                return 1;
            } else if (statusCode == 401) {
                System.err.println("✗ Error: Unauthorized (HTTP 401) - Missing or invalid admin Bearer token (provide with --token).");
                return 1;
            } else if (statusCode == 403) {
                System.err.println("✗ Error: Forbidden (HTTP 403) - Insufficient permissions to trigger emergency kill-switch.");
                return 1;
            } else {
                System.err.println("✗ Error: Kill-switch request failed with HTTP " + statusCode + ": " + responseBody);
                return 1;
            }

        } catch (Exception e) {
            System.err.println("✗ Error: Failed to connect to AegisMCP Gateway at '" + targetEndpoint + "': " + e.getMessage());
            return 1;
        }
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public void setGatewayUrl(String gatewayUrl) {
        this.gatewayUrl = gatewayUrl;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setTargetType(String targetType) {
        this.targetType = targetType;
    }

    public void setConfirmLockdown(boolean confirmLockdown) {
        this.confirmLockdown = confirmLockdown;
    }
}
