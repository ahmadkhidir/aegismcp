package dev.aegismcp.gateway.killswitch;

import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe manager for emergency global lockdown and multi-granularity quarantines.
 * Enforces immediate connection severing and non-blocking tool call rejection.
 * Anchors: FEAT-010, C-001, C-008.
 */
public class KillSwitchManager {

    private static final Logger logger = LoggerFactory.getLogger(KillSwitchManager.class);

    private final AtomicBoolean globalLockdown = new AtomicBoolean(false);
    private volatile QuarantineEntry globalLockdownEntry = null;

    private final ConcurrentHashMap<String, QuarantineEntry> quarantinedAgents = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, QuarantineEntry> quarantinedTools = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, QuarantineEntry> quarantinedServers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> toolToServerMap = new ConcurrentHashMap<>();

    // Active session tracking: agentId -> set of channels, serverId -> set of channels
    private final ConcurrentHashMap<String, Set<Channel>> agentChannels = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<Channel>> serverChannels = new ConcurrentHashMap<>();
    private final Set<Channel> allChannels = ConcurrentHashMap.newKeySet();

    public KillSwitchManager() {
    }

    /**
     * Registers an active transport channel associated with an agent workload and optional upstream server.
     */
    public void registerSession(String agentId, String serverId, Channel channel) {
        if (channel == null) {
            return;
        }
        allChannels.add(channel);
        if (agentId != null && !agentId.isBlank()) {
            agentChannels.computeIfAbsent(agentId, k -> ConcurrentHashMap.newKeySet()).add(channel);
        }
        if (serverId != null && !serverId.isBlank()) {
            serverChannels.computeIfAbsent(serverId, k -> ConcurrentHashMap.newKeySet()).add(channel);
        }

        channel.closeFuture().addListener(f -> unregisterSession(channel));
    }

    public void registerSession(String agentId, Channel channel) {
        registerSession(agentId, null, channel);
    }

    public void unregisterSession(Channel channel) {
        if (channel == null) {
            return;
        }
        allChannels.remove(channel);
        agentChannels.values().forEach(set -> set.remove(channel));
        serverChannels.values().forEach(set -> set.remove(channel));
    }

    /**
     * Associates a tool name with its upstream server ID.
     */
    public void registerToolServerMapping(String toolName, String serverId) {
        if (toolName != null && serverId != null) {
            toolToServerMap.put(toolName, serverId);
        }
    }

    /**
     * Executes quarantine based on target type and target identifier.
     *
     * @param targetType GLOBAL, AGENT, TOOL, or SERVER
     * @param targetId   Target identifier (or "global" / "*" for GLOBAL)
     * @param reason     Human or automated reason for quarantine
     * @return QuarantineResult with affected sessions and status
     */
    public QuarantineResult quarantine(KillTargetType targetType, String targetId, String reason) {
        Objects.requireNonNull(targetType, "targetType must not be null");
        String safeReason = (reason != null && !reason.isBlank()) ? reason : "Emergency quarantine triggered";

        return switch (targetType) {
            case GLOBAL -> {
                int affected = activateGlobalLockdown(safeReason);
                yield QuarantineResult.active(affected);
            }
            case AGENT -> {
                int affected = quarantineAgent(targetId, safeReason);
                yield QuarantineResult.quarantined(affected);
            }
            case TOOL -> {
                int affected = quarantineTool(targetId, safeReason);
                yield QuarantineResult.quarantined(affected);
            }
            case SERVER -> {
                int affected = quarantineServer(targetId, safeReason);
                yield QuarantineResult.severed(affected);
            }
        };
    }

    /**
     * Activates global emergency lockdown, immediately severing all active transport connections.
     *
     * @return number of affected/closed sessions
     */
    public int activateGlobalLockdown(String reason) {
        globalLockdown.set(true);
        globalLockdownEntry = new QuarantineEntry(KillTargetType.GLOBAL, "global", reason, Instant.now());
        logger.warn("GLOBAL EMERGENCY LOCKDOWN ACTIVATED: {}", reason);

        int closed = closeChannels(allChannels);
        allChannels.clear();
        agentChannels.clear();
        serverChannels.clear();
        return closed;
    }

    /**
     * Deactivates global emergency lockdown.
     */
    public void deactivateGlobalLockdown() {
        globalLockdown.set(false);
        globalLockdownEntry = null;
        logger.info("Global emergency lockdown deactivated.");
    }

    public boolean isGlobalLockdown() {
        return globalLockdown.get();
    }

    public QuarantineEntry getGlobalLockdownEntry() {
        return globalLockdownEntry;
    }

    /**
     * Quarantines an agent workload and severs its active transport sessions.
     *
     * @return number of closed sessions
     */
    public int quarantineAgent(String agentId, String reason) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        quarantinedAgents.put(agentId, new QuarantineEntry(KillTargetType.AGENT, agentId, reason, Instant.now()));
        logger.warn("Agent '{}' quarantined: {}", agentId, reason);

        Set<Channel> channels = agentChannels.remove(agentId);
        return channels != null ? closeChannels(channels) : 0;
    }

    public void unquarantineAgent(String agentId) {
        if (agentId != null) {
            quarantinedAgents.remove(agentId);
            logger.info("Agent '{}' quarantine removed.", agentId);
        }
    }

    public boolean isAgentQuarantined(String agentId) {
        return agentId != null && quarantinedAgents.containsKey(agentId);
    }

    /**
     * Quarantines a tool name, blocking all subsequent invocations across all agents.
     */
    public int quarantineTool(String toolName, String reason) {
        Objects.requireNonNull(toolName, "toolName must not be null");
        quarantinedTools.put(toolName, new QuarantineEntry(KillTargetType.TOOL, toolName, reason, Instant.now()));
        logger.warn("Tool '{}' quarantined: {}", toolName, reason);
        return 0;
    }

    public void unquarantineTool(String toolName) {
        if (toolName != null) {
            quarantinedTools.remove(toolName);
            logger.info("Tool '{}' quarantine removed.", toolName);
        }
    }

    public boolean isToolQuarantined(String toolName) {
        return toolName != null && quarantinedTools.containsKey(toolName);
    }

    /**
     * Quarantines an upstream server and severs its transport channels.
     */
    public int quarantineServer(String serverId, String reason) {
        Objects.requireNonNull(serverId, "serverId must not be null");
        quarantinedServers.put(serverId, new QuarantineEntry(KillTargetType.SERVER, serverId, reason, Instant.now()));
        logger.warn("Upstream server '{}' severed/quarantined: {}", serverId, reason);

        Set<Channel> channels = serverChannels.remove(serverId);
        return channels != null ? closeChannels(channels) : 0;
    }

    public void unquarantineServer(String serverId) {
        if (serverId != null) {
            quarantinedServers.remove(serverId);
            logger.info("Upstream server '{}' quarantine removed.", serverId);
        }
    }

    public boolean isServerQuarantined(String serverId) {
        return serverId != null && quarantinedServers.containsKey(serverId);
    }

    /**
     * Checks if any quarantine or global lockdown is currently active.
     */
    public boolean hasActiveQuarantines() {
        return isGlobalLockdown()
                || !quarantinedAgents.isEmpty()
                || !quarantinedTools.isEmpty()
                || !quarantinedServers.isEmpty();
    }

    /**
     * Resets a specific quarantine or global lockdown.
     */
    public void reset(KillTargetType targetType, String targetId) {
        if (targetType == null) {
            return;
        }
        switch (targetType) {
            case GLOBAL -> deactivateGlobalLockdown();
            case AGENT -> unquarantineAgent(targetId);
            case TOOL -> unquarantineTool(targetId);
            case SERVER -> unquarantineServer(targetId);
        }
    }

    /**
     * Resets all active quarantines and lifts global lockdown.
     */
    public void resetAll() {
        deactivateGlobalLockdown();
        quarantinedAgents.clear();
        quarantinedTools.clear();
        quarantinedServers.clear();
        logger.info("All quarantines and lockdowns reset.");
    }

    public Map<String, QuarantineEntry> getQuarantinedAgents() {
        return Collections.unmodifiableMap(quarantinedAgents);
    }

    public Map<String, QuarantineEntry> getQuarantinedTools() {
        return Collections.unmodifiableMap(quarantinedTools);
    }

    public Map<String, QuarantineEntry> getQuarantinedServers() {
        return Collections.unmodifiableMap(quarantinedServers);
    }

    /**
     * Creates a ToolCallInterceptor that enforces kill-switch quarantines.
     */
    public ToolCallInterceptor asInterceptor() {
        return (context, request) -> {
            // 1. Check global emergency lockdown
            if (isGlobalLockdown()) {
                String reason = globalLockdownEntry != null ? globalLockdownEntry.reason() : "Active lockdown";
                return CompletableFuture.completedFuture(InterceptionVerdict.block(
                        new JsonRpcError(-32001, "Policy Violation: Global emergency lockdown is active: " + reason)
                ));
            }

            // 2. Check agent quarantine
            String agentId = (context != null && context.identity() != null) ? context.identity().agentId() : null;
            if (agentId != null && isAgentQuarantined(agentId)) {
                QuarantineEntry entry = quarantinedAgents.get(agentId);
                String reason = entry != null ? entry.reason() : "Agent quarantined";
                return CompletableFuture.completedFuture(InterceptionVerdict.block(
                        new JsonRpcError(-32001, "Policy Violation: Agent '" + agentId + "' is quarantined: " + reason)
                ));
            }

            // 3. Check tool quarantine for tool invocations
            if (request != null && request.isToolCall()) {
                String tool = request.toolName();
                if (tool != null) {
                    if (isToolQuarantined(tool)) {
                        QuarantineEntry entry = quarantinedTools.get(tool);
                        String reason = entry != null ? entry.reason() : "Tool quarantined";
                        return CompletableFuture.completedFuture(InterceptionVerdict.block(
                                new JsonRpcError(-32001, "Policy Violation: Tool '" + tool + "' is quarantined: " + reason)
                        ));
                    }

                    // Check server quarantine if tool is mapped to an upstream server
                    String mappedServerId = toolToServerMap.get(tool);
                    if (mappedServerId != null && isServerQuarantined(mappedServerId)) {
                        QuarantineEntry entry = quarantinedServers.get(mappedServerId);
                        String reason = entry != null ? entry.reason() : "Server quarantined";
                        return CompletableFuture.completedFuture(InterceptionVerdict.block(
                                new JsonRpcError(-32001, "Policy Violation: Upstream server '" + mappedServerId + "' is severed: " + reason)
                        ));
                    }
                }
            }

            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
    }

    private int closeChannels(Set<Channel> channels) {
        int closed = 0;
        for (Channel ch : channels) {
            try {
                if (ch != null && (ch.isActive() || ch.isOpen())) {
                    ch.close();
                    closed++;
                }
            } catch (Exception e) {
                logger.warn("Error closing channel during emergency quarantine", e);
            }
        }
        return closed;
    }
}
