package dev.aegismcp.gateway.approval;

import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyEvaluationResult;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Human-in-the-Loop approval manager holding active approval tickets and suspending execution.
 * Intercepts tool calls flagged with REQUIRE_APPROVAL, suspends the async pipeline,
 * enforces TTL timeouts, and resumes or rejects execution upon human operator decisions.
 * Conforms to contracts C-003 and C-004.
 * Anchors: FEAT-006, C-003, C-004, NFR-001.
 */
public class ApprovalManager implements DeclarativePolicyInterceptor.ApprovalHandler, AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalManager.class);
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    public static final double DEFAULT_RISK_SCORE = 85.0;

    private final Duration defaultTtl;
    private final ScheduledExecutorService scheduler;
    private final boolean ownsScheduler;

    private final ConcurrentMap<String, ActiveTicket> activeTickets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ApprovalTicket> ticketStore = new ConcurrentHashMap<>();

    private record ActiveTicket(
            ApprovalTicket ticket,
            CompletableFuture<InterceptionVerdict> future,
            ScheduledFuture<?> timeoutTask
    ) {
    }

    public ApprovalManager() {
        this(DEFAULT_TTL);
    }

    public ApprovalManager(Duration defaultTtl) {
        this(
                defaultTtl,
                Executors.newSingleThreadScheduledExecutor(
                        Thread.ofPlatform().name("aegis-approval-timeout-", 0).daemon(true).factory()
                ),
                true
        );
    }

    public ApprovalManager(Duration defaultTtl, ScheduledExecutorService scheduler) {
        this(defaultTtl, scheduler, false);
    }

    private ApprovalManager(Duration defaultTtl, ScheduledExecutorService scheduler, boolean ownsScheduler) {
        this.defaultTtl = Objects.requireNonNull(defaultTtl, "defaultTtl must not be null");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler must not be null");
        this.ownsScheduler = ownsScheduler;
    }

    @Override
    public CompletableFuture<InterceptionVerdict> handleApproval(
            SecurityContext context,
            JsonRpcRequest request,
            PolicyEvaluationResult result
    ) {
        String agentId = (context != null && context.identity() != null)
                ? context.identity().agentId()
                : "agent_unknown";

        String triggerPolicyId = (result != null && result.policyId() != null)
                ? result.policyId()
                : "default";

        return createAndSuspendTicket(
                agentId,
                request.toolName(),
                request.toolArguments(),
                DEFAULT_RISK_SCORE,
                triggerPolicyId,
                defaultTtl
        );
    }

    /**
     * Creates an approval ticket, records it, and returns a suspended future.
     */
    public CompletableFuture<InterceptionVerdict> createAndSuspendTicket(
            String agentId,
            String toolName,
            com.fasterxml.jackson.databind.JsonNode arguments,
            double riskScore,
            String triggerPolicyId,
            Duration ttl
    ) {
        String ticketId = "appr_" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);

        ApprovalTicket ticket = new ApprovalTicket(
                ticketId,
                agentId,
                toolName,
                arguments,
                riskScore,
                ApprovalStatus.PENDING.getValue(),
                now.toString(),
                expiresAt.toString(),
                null,
                null,
                triggerPolicyId
        );

        CompletableFuture<InterceptionVerdict> future = new CompletableFuture<>();

        ScheduledFuture<?> timeoutTask = scheduler.schedule(() -> {
            expireTicket(ticketId);
        }, ttl.toMillis(), TimeUnit.MILLISECONDS);

        ActiveTicket activeTicket = new ActiveTicket(ticket, future, timeoutTask);
        activeTickets.put(ticketId, activeTicket);
        ticketStore.put(ticketId, ticket);

        // FEAT-006: If agent disconnects or pipeline cancels future, cancel approval ticket
        future.whenComplete((verdict, throwable) -> {
            if (future.isCancelled()) {
                cancelTicket(ticketId);
            }
        });

        logger.info("Created pending approval ticket {} for agent {} invoking tool {} (TTL: {}s)",
                ticketId, agentId, toolName, ttl.toSeconds());

        return future;
    }

    /**
     * Operator submits an authorization decision (APPROVE or REJECT) conforming to contract C-004.
     */
    public ApprovalDto.DecisionResponse submitDecision(
            String ticketId,
            String decisionStr,
            String reviewer,
            String reason
    ) {
        if (ticketId == null || ticketId.isBlank()) {
            throw new ApprovalException.TicketNotFoundException("Empty ticket ID");
        }

        ApprovalDecision decision;
        try {
            decision = ApprovalDecision.fromString(decisionStr);
        } catch (IllegalArgumentException e) {
            throw new ApprovalException.InvalidDecisionException(e.getMessage());
        }

        ApprovalTicket existing = ticketStore.get(ticketId);
        if (existing == null) {
            throw new ApprovalException.TicketNotFoundException(ticketId);
        }

        if (ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(existing.status()) || existing.isExpired()) {
            throw new ApprovalException.TicketNotFoundException(ticketId + " has expired or timed out");
        }

        if (ApprovalStatus.APPROVED.getValue().equalsIgnoreCase(existing.status()) ||
                ApprovalStatus.REJECTED.getValue().equalsIgnoreCase(existing.status())) {
            throw new ApprovalException.TicketAlreadyResolvedException(ticketId, existing.status());
        }

        ActiveTicket active = activeTickets.remove(ticketId);
        if (active == null) {
            // Concurrent resolution
            ApprovalTicket recheck = ticketStore.get(ticketId);
            if (recheck != null && !recheck.isPending()) {
                throw new ApprovalException.TicketAlreadyResolvedException(ticketId, recheck.status());
            }
            throw new ApprovalException.TicketNotFoundException(ticketId);
        }

        // Cancel the scheduled timeout task
        active.timeoutTask().cancel(false);

        ApprovalStatus newStatus = (decision == ApprovalDecision.APPROVE)
                ? ApprovalStatus.APPROVED
                : ApprovalStatus.REJECTED;

        ApprovalTicket resolvedTicket = active.ticket().withDecision(newStatus, reviewer, reason);
        ticketStore.put(ticketId, resolvedTicket);

        String processedAt = Instant.now().toString();

        if (decision == ApprovalDecision.APPROVE) {
            logger.info("Approval ticket {} APPROVED by reviewer '{}'", ticketId, reviewer);
            active.future().complete(InterceptionVerdict.allow());
        } else {
            logger.info("Approval ticket {} REJECTED by reviewer '{}': {}", ticketId, reviewer, reason);
            String denialReason = (reason != null && !reason.isBlank())
                    ? reason
                    : "Explicit rejection by operator";
            active.future().complete(
                    InterceptionVerdict.block(JsonRpcError.policyViolation("Tool execution rejected by reviewer: " + denialReason))
            );
        }

        return new ApprovalDto.DecisionResponse(ticketId, decision.name(), processedAt);
    }

    /**
     * Automatically called when a ticket's TTL expires.
     */
    private void expireTicket(String ticketId) {
        ActiveTicket active = activeTickets.remove(ticketId);
        if (active != null) {
            ApprovalTicket existing = ticketStore.get(ticketId);
            if (existing != null && existing.isPending()) {
                ApprovalTicket timedOut = existing.withDecision(
                        ApprovalStatus.TIMED_OUT,
                        "system",
                        "Approval deadline expired"
                );
                ticketStore.put(ticketId, timedOut);
            }

            logger.warn("Approval ticket {} TIMED OUT after {}s", ticketId, defaultTtl.toSeconds());
            active.future().complete(
                    InterceptionVerdict.block(JsonRpcError.approvalTimedOut(
                            "Approval request timed out after " + defaultTtl.toSeconds() + " seconds"
                    ))
            );
        }
    }

    /**
     * Cancels a pending ticket when the client disconnects or request cancels.
     */
    public void cancelTicket(String ticketId) {
        ActiveTicket active = activeTickets.remove(ticketId);
        if (active != null) {
            active.timeoutTask().cancel(false);
            ApprovalTicket existing = ticketStore.get(ticketId);
            if (existing != null && existing.isPending()) {
                ApprovalTicket cancelled = existing.withDecision(
                        ApprovalStatus.REJECTED,
                        "system",
                        "Client request cancelled or connection dropped"
                );
                ticketStore.put(ticketId, cancelled);
            }
            logger.info("Pending approval ticket {} cancelled due to client disconnect", ticketId);
        }
    }

    /**
     * Retrieves tickets conforming to C-003, optionally filtered by status.
     */
    public List<ApprovalTicket> getTickets(String statusFilter) {
        if (statusFilter == null || statusFilter.isBlank()) {
            return new ArrayList<>(ticketStore.values());
        }

        String filter = statusFilter.trim().toLowerCase();
        if ("expired".equals(filter)) {
            filter = ApprovalStatus.TIMED_OUT.getValue();
        }

        final String targetStatus = filter;
        List<ApprovalTicket> filtered = new ArrayList<>();
        for (ApprovalTicket ticket : ticketStore.values()) {
            if (ticket.status().equalsIgnoreCase(targetStatus)) {
                filtered.add(ticket);
            }
        }
        return filtered;
    }

    public Optional<ApprovalTicket> getTicket(String ticketId) {
        return Optional.ofNullable(ticketStore.get(ticketId));
    }

    public int getActiveTicketCount() {
        return activeTickets.size();
    }

    public int getTotalTicketCount() {
        return ticketStore.size();
    }

    public void clear() {
        for (ActiveTicket active : activeTickets.values()) {
            active.timeoutTask().cancel(true);
            active.future().cancel(true);
        }
        activeTickets.clear();
        ticketStore.clear();
    }

    @Override
    public void close() {
        clear();
        if (ownsScheduler) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scheduler.shutdownNow();
            }
        }
    }
}
