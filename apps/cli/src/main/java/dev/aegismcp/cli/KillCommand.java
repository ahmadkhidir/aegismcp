package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.killswitch.KillSwitchDto;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Command line action to invoke the emergency kill-switch and circuit breaker.
 *
 * <p>Conforms to contract C-008 exactly: a {@code session}, {@code agent}, or {@code server}
 * target carries its identifier, while a {@code global} target carries none and requires
 * {@code --confirm-lockdown}. The {@code tool} granularity is an internal circuit-breaker target
 * and is not part of the management vocabulary, so it is neither accepted nor advertised.
 * {@code --second-approver} is forwarded only for a {@code global} target; whether it is required
 * depends on the gateway's deployment tier, which the CLI does not guess.
 *
 * <p>Every documented refusal is mapped to a documented exit code: a malformed request
 * ({@code 400}) is a usage error ({@link ExitCode#USAGE}); authentication, authorization, missing
 * target, transport, and propagation failures are {@link ExitCode#FAILURE}. Gateway error bodies are
 * reduced to a redacted reason rather than echoed.
 *
 * <p>Anchors: FEAT-010, FEAT-003, C-008.
 */
@Command(
        name = "kill",
        description = "Trigger the emergency kill-switch to quarantine rogue agents or sever compromised MCP connections (C-008)",
        mixinStandardHelpOptions = true
)
public class KillCommand implements Callable<Integer> {

    private static final Set<String> CONTRACT_TARGET_TYPES = Set.of("session", "agent", "server", "global");

    private static final String KILL_PATH = "/api/v1/emergency/kill";

    @Option(names = {"-a", "--agent"}, description = "Agent identifier to quarantine; shorthand for --target-type agent --target-id <id>")
    private String agentId;

    @Option(names = {"--target-type"}, description = "Target type: session, agent, server, or global")
    private String targetType;

    @Option(names = {"--target-id"}, description = "Session identifier, agent identity, or upstream server identifier (required for session, agent, and server; omitted for global)")
    private String targetId;

    @Option(names = {"-g", "--gateway"}, defaultValue = "http://localhost:8080", description = "AegisMCP Gateway base URL (default: http://localhost:8080)")
    private String gatewayUrl;

    @Option(names = {"-r", "--reason"}, description = "Operational reason recorded in the audit ledger")
    private String reason;

    @Option(names = {"-t", "--token"}, description = "Operator OIDC access token for the Authorization header")
    private String token;

    @Option(names = {"--second-approver"}, description = "Second operator identity confirming an Enterprise production global lockdown")
    private String secondApprover;

    @Option(names = {"--confirm-lockdown"}, description = "Explicit confirmation required to trigger a global lockdown")
    private boolean confirmLockdown;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final DlpScrubber dlpScrubber;

    public KillCommand() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                new ObjectMapper(), DlpScrubber.getInstance());
    }

    public KillCommand(HttpClient httpClient, ObjectMapper mapper) {
        this(httpClient, mapper, DlpScrubber.getInstance());
    }

    public KillCommand(HttpClient httpClient, ObjectMapper mapper, DlpScrubber dlpScrubber) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.mapper = Objects.requireNonNull(mapper, "mapper must not be null");
        this.dlpScrubber = Objects.requireNonNull(dlpScrubber, "dlpScrubber must not be null");
    }

    @Override
    public Integer call() {
        Target target = resolveTarget();
        if (target == null) {
            return ExitCode.USAGE;
        }

        if ("global".equals(target.type()) && !confirmLockdown) {
            System.err.println("Error: A global lockdown requires the explicit --confirm-lockdown flag.");
            return ExitCode.USAGE;
        }

        String approver = trimToNull(secondApprover);
        if (approver != null && !"global".equals(target.type())) {
            System.err.println("Error: --second-approver is permitted only on a global target.");
            return ExitCode.USAGE;
        }

        URI endpoint;
        try {
            endpoint = killEndpoint();
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return ExitCode.USAGE;
        }

        KillSwitchDto.KillRequest killRequest = new KillSwitchDto.KillRequest(
                target.type(),
                target.id(),
                trimToNull(reason),
                approver);

        String jsonPayload;
        try {
            jsonPayload = mapper.writeValueAsString(killRequest);
        } catch (Exception e) {
            System.err.println("Error: Failed to build the C-008 request body.");
            return ExitCode.FAILURE;
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(endpoint)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload));

        String bearerToken = trimToNull(token);
        if (bearerToken != null) {
            requestBuilder.header("Authorization", "Bearer " + bearerToken);
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Error: The kill request was interrupted.");
            return ExitCode.INTERRUPTED;
        } catch (Exception e) {
            System.err.println("Error: Failed to connect to AegisMCP Gateway at '" + endpoint + "': "
                    + dlpScrubber.scrubText(e.getMessage()));
            return ExitCode.FAILURE;
        }

        return handleResponse(target, response.statusCode(), response.body());
    }

    /** A validated C-008 target: a contract target type and, for scoped targets, its identifier. */
    private record Target(String type, String id) {
    }

    /**
     * Validates the target selectors before any request is built. Prints the usage reason and
     * returns null when the combination is invalid.
     */
    private Target resolveTarget() {
        String agent = trimToNull(agentId);
        String requestedType = trimToNull(targetType);
        String explicitId = trimToNull(targetId);

        String resolvedType;
        if (agent != null) {
            if (requestedType != null && !"agent".equalsIgnoreCase(requestedType)) {
                System.err.println("Error: --agent is shorthand for the agent target type and cannot be "
                        + "combined with --target-type " + requestedType + ".");
                return null;
            }
            resolvedType = "agent";
        } else if (requestedType == null) {
            System.err.println("Error: A target is required: use --agent <id> or "
                    + "--target-type <session|agent|server|global>.");
            return null;
        } else {
            resolvedType = requestedType.trim().toLowerCase(java.util.Locale.ROOT);
            if (!CONTRACT_TARGET_TYPES.contains(resolvedType)) {
                System.err.println("Error: Invalid --target-type '" + requestedType
                        + "': expected session, agent, server, or global.");
                return null;
            }
        }

        String resolvedId = agent != null ? agent : explicitId;
        if (agent != null && explicitId != null && !agent.equals(explicitId)) {
            System.err.println("Error: --agent and --target-id name different targets.");
            return null;
        }

        if ("global".equals(resolvedType)) {
            if (resolvedId != null) {
                System.err.println("Error: A global target sends no target identifier; remove "
                        + "--agent/--target-id.");
                return null;
            }
            return new Target("global", null);
        }

        if (resolvedId == null) {
            System.err.println("Error: A " + resolvedType + " target requires --target-id (or --agent).");
            return null;
        }
        return new Target(resolvedType, resolvedId);
    }

    private URI killEndpoint() {
        String base = trimToNull(gatewayUrl);
        if (base == null) {
            throw new IllegalArgumentException("--gateway must not be blank.");
        }
        String trimmed = base.replaceAll("/+$", "");
        URI endpoint;
        try {
            endpoint = URI.create(trimmed + KILL_PATH);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid --gateway URL.");
        }
        if (endpoint.getScheme() == null
                || !(endpoint.getScheme().equalsIgnoreCase("http") || endpoint.getScheme().equalsIgnoreCase("https"))
                || endpoint.getHost() == null) {
            throw new IllegalArgumentException("Invalid --gateway URL: expected an absolute http or https URL.");
        }
        return endpoint;
    }

    private int handleResponse(Target target, int statusCode, String responseBody) {
        if (statusCode == 200) {
            return handleSuccess(target, responseBody);
        }

        String reason = redactedGatewayReason(responseBody);
        String detail = reason != null ? " Reason: " + reason : "";

        return switch (statusCode) {
            case 400 -> {
                System.err.println("Error: Bad Request (HTTP 400): the gateway rejected the kill request." + detail);
                yield ExitCode.USAGE;
            }
            case 401 -> {
                System.err.println("Error: Unauthorized (HTTP 401): the access token is missing, expired, "
                        + "or invalid." + detail);
                yield ExitCode.FAILURE;
            }
            case 403 -> {
                System.err.println("Error: Forbidden (HTTP 403): the operator lacks the role, the global "
                        + "multi-factor re-confirmation is missing or stale, or the second approver was "
                        + "not confirmed." + detail);
                yield ExitCode.FAILURE;
            }
            case 404 -> {
                System.err.println("Error: Not Found (HTTP 404): no session, agent, or upstream server "
                        + "matches the target." + detail);
                yield ExitCode.FAILURE;
            }
            case 503 -> {
                System.err.println("Error: Service Unavailable (HTTP 503): the kill signal did not reach "
                        + "every peer gateway node; applied controls remain in force." + detail);
                yield ExitCode.FAILURE;
            }
            default -> {
                System.err.println("Error: The kill request failed with HTTP " + statusCode + "." + detail);
                yield ExitCode.FAILURE;
            }
        };
    }

    private int handleSuccess(Target target, String responseBody) {
        String expectedStatus = switch (target.type()) {
            case "session", "agent" -> "QUARANTINED";
            case "server" -> "SEVERED";
            case "global" -> "LOCKDOWN";
            default -> null;
        };

        KillSwitchDto.KillResponse response;
        try {
            JsonNode tree = mapper.readTree(responseBody);
            if (tree == null || !tree.isObject()
                    || !tree.path("status").isTextual()
                    || !tree.path("affectedSessions").isIntegralNumber()
                    || !tree.path("affectedSessions").canConvertToInt()
                    || !tree.path("timestamp").isTextual()
                    || tree.path("timestamp").asText().isBlank()) {
                return invalidResponse();
            }
            response = mapper.treeToValue(tree, KillSwitchDto.KillResponse.class);
        } catch (Exception e) {
            return invalidResponse();
        }

        if (!expectedStatus.equals(response.status())) {
            System.err.println("Error: The gateway returned HTTP 200 with status '" + response.status()
                    + "' for a " + target.type() + " target; expected '" + expectedStatus + "'.");
            return ExitCode.FAILURE;
        }

        String shownTarget = target.id() != null ? target.type() + " [" + target.id() + "]" : target.type();
        System.out.println("Emergency kill-switch invoked successfully (HTTP 200).");
        System.out.println("  Target:            " + shownTarget);
        System.out.println("  Result Status:     " + response.status());
        System.out.println("  Affected Sessions: " + response.affectedSessions());
        System.out.println("  Timestamp:         " + response.timestamp());
        return ExitCode.SUCCESS;
    }

    private int invalidResponse() {
        System.err.println("Error: The gateway returned HTTP 200 without a valid C-008 response body.");
        return ExitCode.FAILURE;
    }

    /**
     * Extracts the {@code error} field from a gateway body and redacts credentials and PII. The raw
     * body is never printed: it can carry target detail or reflected input.
     */
    private String redactedGatewayReason(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            return null;
        }
        try {
            JsonNode tree = mapper.readTree(responseBody);
            if (tree != null && tree.path("error").isTextual()) {
                String message = tree.path("error").asText();
                return message.isBlank() ? null : dlpScrubber.scrubText(message);
            }
        } catch (Exception ignored) {
            // Not a JSON error body; the status alone is the contract-level answer.
        }
        return null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
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

    public void setTargetId(String targetId) {
        this.targetId = targetId;
    }

    public void setSecondApprover(String secondApprover) {
        this.secondApprover = secondApprover;
    }

    public void setConfirmLockdown(boolean confirmLockdown) {
        this.confirmLockdown = confirmLockdown;
    }
}
