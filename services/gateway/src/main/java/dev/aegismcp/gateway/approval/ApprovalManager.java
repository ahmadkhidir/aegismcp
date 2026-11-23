package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyEvaluationResult;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Human-in-the-Loop approval manager holding active approval tickets and suspending execution.
 * Intercepts tool calls flagged with REQUIRE_APPROVAL, suspends the async pipeline, dispatches an
 * out-of-band notification to every configured destination, enforces TTL timeouts, and resumes or
 * rejects execution upon human operator decisions. Reviewer identity is always the verified
 * operator supplied by the endpoint, never a request-body value.
 *
 * <p>Anchors: FEAT-006, C-003, C-004, C-014, C-019, NFR-001, NFR-002.
 */
public class ApprovalManager implements DeclarativePolicyInterceptor.ApprovalHandler, AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalManager.class);
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    public static final double DEFAULT_RISK_SCORE = 85.0;

    /** The approval token alphabet (RFC 4648 base32) and the token length FEAT-006 fixes. */
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int TOKEN_LENGTH = 26;
    private static final SecureRandom TOKEN_RANDOM = new SecureRandom();

    private final Duration defaultTtl;
    private final ScheduledExecutorService scheduler;
    private final boolean ownsScheduler;
    private final ApprovalNotificationConfig notificationConfig;
    private final ApprovalNotificationDispatcher notificationDispatcher;

    private final ConcurrentMap<String, ActiveTicket> activeTickets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ApprovalTicket> ticketStore = new ConcurrentHashMap<>();

    /**
     * Serializes ticket resolution, expiry, and cancellation so exactly one decision is recorded
     * for a ticket (FEAT-006). Held only for map state changes, never while a suspended future's
     * continuation runs.
     */
    private final Object lifecycleLock = new Object();

    private record ActiveTicket(
            ApprovalTicket ticket,
            CompletableFuture<InterceptionVerdict> future,
            ScheduledFuture<?> timeoutTask
    ) {
    }

    public ApprovalManager() {
        this(DEFAULT_TTL);
    }

    /**
     * Shipped constructor: the TTL comes from the composition root and the out-of-band destinations
     * are resolved from the environment and the gateway YAML document at startup (FEAT-006).
     */
    public ApprovalManager(Duration defaultTtl) {
        this(defaultTtl, ApprovalNotificationConfig.load());
    }

    public ApprovalManager(Duration defaultTtl, ApprovalNotificationConfig notificationConfig) {
        this(defaultTtl, newTimeoutScheduler(), true, notificationConfig, null);
    }

    public ApprovalManager(Duration defaultTtl, ScheduledExecutorService scheduler) {
        this(defaultTtl, scheduler, false, ApprovalNotificationConfig.none(), null);
    }

    /** Test seam: supplies an explicit dispatcher so no destination is contacted. */
    ApprovalManager(
            Duration defaultTtl,
            ApprovalNotificationConfig notificationConfig,
            ApprovalNotificationDispatcher notificationDispatcher
    ) {
        this(defaultTtl, newTimeoutScheduler(), true, notificationConfig, notificationDispatcher);
    }

    private ApprovalManager(
            Duration defaultTtl,
            ScheduledExecutorService scheduler,
            boolean ownsScheduler,
            ApprovalNotificationConfig notificationConfig,
            ApprovalNotificationDispatcher notificationDispatcher
    ) {
        this.defaultTtl = Objects.requireNonNull(defaultTtl, "defaultTtl must not be null");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler must not be null");
        this.ownsScheduler = ownsScheduler;
        this.notificationConfig = Objects.requireNonNull(
                notificationConfig, "notificationConfig must not be null");
        this.notificationDispatcher = notificationDispatcher != null
                ? notificationDispatcher
                : createDispatcher(notificationConfig);
    }

    private static ScheduledExecutorService newTimeoutScheduler() {
        return Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("aegis-approval-timeout-", 0).daemon(true).factory());
    }

    /** Builds one channel per configured destination; an unconfigured deployment has none. */
    private static ApprovalNotificationDispatcher createDispatcher(
            ApprovalNotificationConfig config
    ) {
        List<ApprovalNotificationChannel> channels = new ArrayList<>();
        if (config.anyConfigured()) {
            HttpClient httpClient = HttpClient.newBuilder()
                    .connectTimeout(config.requestTimeout())
                    .build();
            if (config.slackConfigured()) {
                channels.add(new SlackApprovalNotifier(
                        config.slack().webhookUrl(), httpClient, config.requestTimeout()));
            }
            if (config.webhookConfigured()) {
                channels.add(new WebhookApprovalNotifier(
                        config.webhookUrl(), httpClient, config.requestTimeout(), config.consoleBaseUrl()));
            }
            if (config.emailConfigured()) {
                channels.add(new SmtpApprovalNotifier(config.email(), config.consoleBaseUrl()));
            }
        }
        return new ApprovalNotificationDispatcher(
                channels, config.maxAttempts(), config.retryBackoff());
    }

    /** The destination configuration this manager dispatches to. */
    public ApprovalNotificationConfig notificationConfig() {
        return notificationConfig;
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
                null,
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
        return createAndSuspendTicket(agentId, toolName, arguments, riskScore, triggerPolicyId, null, ttl);
    }

    /**
     * Creates an approval ticket carrying the agent's own justification, records it, and returns a
     * suspended future.
     */
    public CompletableFuture<InterceptionVerdict> createAndSuspendTicket(
            String agentId,
            String toolName,
            com.fasterxml.jackson.databind.JsonNode arguments,
            double riskScore,
            String triggerPolicyId,
            String agentIntent,
            Duration ttl
    ) {
        String ticketId = newTicketId();
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
                triggerPolicyId,
                agentIntent,
                null
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

        dispatchNotification(ticket);

        logger.info("Created pending approval ticket {} for agent {} invoking tool {} (TTL: {}s)",
                ticketId, agentId, toolName, ttl.toSeconds());

        return future;
    }

    /**
     * Starts out-of-band delivery for a freshly suspended call. Delivery is asynchronous and may
     * fail without denying the call: the ticket stays pending and reachable in the console queue
     * until it is decided or expires (FEAT-006).
     */
    private void dispatchNotification(ApprovalTicket ticket) {
        try {
            notificationDispatcher.dispatch(ticket);
        } catch (RuntimeException e) {
            logger.warn("Approval notification for ticket {} could not be scheduled: {}",
                    ticket.id(), e.getClass().getSimpleName());
        }
    }

    /**
     * Builds an opaque, unguessable ticket token rendered as {@code appr_} followed by 26 base32
     * characters, as FEAT-006 fixes: 130 bits of {@link SecureRandom} entropy.
     */
    static String newTicketId() {
        byte[] entropy = new byte[17];
        TOKEN_RANDOM.nextBytes(entropy);
        return "appr_" + base32(entropy).substring(0, TOKEN_LENGTH);
    }

    private static String base32(byte[] data) {
        StringBuilder encoded = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte value : data) {
            buffer = (buffer << 8) | (value & 0xFF);
            bits += 8;
            while (bits >= 5) {
                encoded.append(BASE32_ALPHABET.charAt((buffer >> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
        }
        return encoded.toString();
    }

    /**
     * Approves a pending ticket on behalf of the verified reviewer named by the caller's token
     * (C-004). The suspended JSON-RPC call is released before this method returns.
     */
    public ApprovalTicket approve(String ticketId, String reviewer) {
        return resolve(ticketId, ApprovalDecision.APPROVE, reviewer, null);
    }

    /**
     * Rejects a pending ticket on behalf of the verified reviewer (C-014). The supplied reason is
     * delivered to the requesting agent and recorded with the ticket.
     */
    public ApprovalTicket reject(String ticketId, String reviewer, String reason) {
        if (reason == null || reason.isBlank()) {
            throw new ApprovalException.InvalidDecisionException(
                    "Invalid rejection payload: 'reason' is required and must not be blank");
        }
        return resolve(ticketId, ApprovalDecision.REJECT, reviewer, reason);
    }

    private ApprovalTicket resolve(
            String ticketId,
            ApprovalDecision decision,
            String reviewer,
            String reason
    ) {
        if (ticketId == null || ticketId.isBlank()) {
            throw new ApprovalException.TicketNotFoundException("Empty ticket ID");
        }
        if (reviewer == null || reviewer.isBlank()) {
            // The reviewer comes from the verified token; an empty subject means the caller was
            // never authenticated and the decision must not be attributed to anyone.
            throw new ApprovalException.InvalidDecisionException("Reviewer identity is required");
        }

        ApprovalTicket resolvedTicket;
        CompletableFuture<InterceptionVerdict> futureToRelease;
        // The decision and the state transition are one critical section so two approvers clicking
        // at the same instant cannot both win: the second sees the resolved ticket and reports it
        // (FEAT-006). The suspended future is completed outside the lock so a proxy continuation
        // never runs while the lifecycle lock is held.
        synchronized (lifecycleLock) {
            ApprovalTicket existing = ticketStore.get(ticketId);
            if (existing == null) {
                throw new ApprovalException.TicketNotFoundException(ticketId);
            }

            // A resolved ticket reports its recorded outcome even if its TTL has since elapsed, so a
            // late button click or a Slack redelivery never contradicts the decision already sealed.
            if (ApprovalStatus.APPROVED.getValue().equalsIgnoreCase(existing.status())
                    || ApprovalStatus.REJECTED.getValue().equalsIgnoreCase(existing.status())) {
                throw new ApprovalException.TicketAlreadyResolvedException(
                        ticketId, existing.status(), existing.reviewer());
            }

            if (ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(existing.status())
                    || existing.isExpired()) {
                throw new ApprovalException.TicketExpiredException(ticketId);
            }

            ActiveTicket active = activeTickets.remove(ticketId);
            if (active == null) {
                ApprovalTicket recheck = ticketStore.get(ticketId);
                if (recheck != null && !recheck.isPending()) {
                    throw new ApprovalException.TicketAlreadyResolvedException(
                            ticketId, recheck.status(), recheck.reviewer());
                }
                throw new ApprovalException.TicketNotFoundException(ticketId);
            }

            active.timeoutTask().cancel(false);

            ApprovalStatus newStatus = (decision == ApprovalDecision.APPROVE)
                    ? ApprovalStatus.APPROVED
                    : ApprovalStatus.REJECTED;

            String processedAt = Instant.now().toString();
            String recordedReason = (decision == ApprovalDecision.APPROVE) ? null : reason;
            resolvedTicket = active.ticket().withDecision(newStatus, reviewer, recordedReason, processedAt);
            ticketStore.put(ticketId, resolvedTicket);
            futureToRelease = active.future();
        }

        if (decision == ApprovalDecision.APPROVE) {
            logger.info("Approval ticket {} approved by reviewer {}", ticketId, reviewer);
            futureToRelease.complete(InterceptionVerdict.allow());
        } else {
            logger.info("Approval ticket {} rejected by reviewer {}", ticketId, reviewer);
            futureToRelease.complete(
                    InterceptionVerdict.block(approvalDenied(
                            "Tool execution rejected by reviewer: " + reason))
            );
        }

        return resolvedTicket;
    }

    /**
     * The C-001 rejection row: {@code -32002} with machine code {@code APPROVAL_DENIED}, answered to
     * the agent as HTTP 403. The numeric code is shared with the approval timeout, so the machine
     * code is what selects the {@code APPROVAL_DENIED} status family.
     */
    private static JsonRpcError approvalDenied(String details) {
        ObjectNode data = JsonNodeFactory.instance.objectNode();
        data.put("code", JsonRpcError.MACHINE_APPROVAL_DENIED);
        return new JsonRpcError(JsonRpcError.APPROVAL_TIMED_OUT, "Approval Denied: " + details, data);
    }

    /**
     * Automatically called when a ticket's TTL expires.
     */
    private void expireTicket(String ticketId) {
        ActiveTicket active;
        long ttlSeconds;
        synchronized (lifecycleLock) {
            active = activeTickets.remove(ticketId);
            if (active == null) {
                return;
            }
            ApprovalTicket existing = ticketStore.get(ticketId);
            if (existing != null && existing.isPending()) {
                ApprovalTicket timedOut = existing.withDecision(
                        ApprovalStatus.TIMED_OUT,
                        "system",
                        "Approval deadline expired",
                        existing.expiresAt()
                );
                ticketStore.put(ticketId, timedOut);
            }
            ttlSeconds = ttlSeconds(active.ticket());
        }

        logger.warn("Approval ticket {} timed out after {}s", ticketId, ttlSeconds);
        active.future().complete(
                InterceptionVerdict.block(JsonRpcError.approvalTimedOut(
                        "Approval request timed out after " + ttlSeconds + " seconds"
                ))
        );
    }

    /** The ticket's own requested-to-expiry window, so a per-call TTL is reported accurately. */
    private static long ttlSeconds(ApprovalTicket ticket) {
        try {
            return Duration.between(
                    Instant.parse(ticket.requestedAt()), Instant.parse(ticket.expiresAt())).toSeconds();
        } catch (RuntimeException e) {
            return DEFAULT_TTL.toSeconds();
        }
    }

    /**
     * Cancels a pending ticket when the client disconnects or request cancels.
     */
    public void cancelTicket(String ticketId) {
        synchronized (lifecycleLock) {
            ActiveTicket active = activeTickets.remove(ticketId);
            if (active == null) {
                return;
            }
            active.timeoutTask().cancel(false);
            ApprovalTicket existing = ticketStore.get(ticketId);
            if (existing != null && existing.isPending()) {
                ApprovalTicket cancelled = existing.withDecision(
                        ApprovalStatus.REJECTED,
                        "system",
                        "Agent session cancelled while the ticket was pending",
                        Instant.now().toString()
                );
                ticketStore.put(ticketId, cancelled);
            }
        }
        logger.info("Pending approval ticket {} cancelled due to client disconnect", ticketId);
    }

    /**
     * Pending tickets ordered by expiry ascending so the least remaining time-to-live appears
     * first (C-003), capped at the requested limit.
     */
    public List<ApprovalTicket> getPendingTickets(int limit) {
        List<ApprovalTicket> pending = new ArrayList<>();
        for (ApprovalTicket ticket : ticketStore.values()) {
            if (ticket.isPending() && !ticket.isExpired()) {
                pending.add(ticket);
            }
        }
        pending.sort(Comparator.comparing(ApprovalTicket::expiresAt));
        if (limit > 0 && pending.size() > limit) {
            return List.copyOf(pending.subList(0, limit));
        }
        return List.copyOf(pending);
    }

    /**
     * Resolved tickets filtered by the history status, ordered by resolution time descending
     * (C-019). {@code expired} maps to tickets that failed closed on their TTL.
     */
    public HistoryPage getHistory(String status, int limit, int offset) {
        if (status == null || status.isBlank()) {
            throw new ApprovalException.InvalidDecisionException("Query parameter 'status' is required");
        }

        String normalized = status.trim().toLowerCase();
        List<ApprovalTicket> matching = new ArrayList<>();
        for (ApprovalTicket ticket : ticketStore.values()) {
            if (matchesHistoryStatus(ticket, normalized)) {
                matching.add(ticket);
            }
        }
        matching.sort(Comparator.comparing(
                (ApprovalTicket ticket) -> ticket.processedAt() != null ? ticket.processedAt() : ticket.expiresAt()
        ).reversed());

        int total = matching.size();
        int fromIndex = Math.min(Math.max(offset, 0), total);
        int toIndex = Math.min(fromIndex + Math.max(limit, 0), total);
        return new HistoryPage(List.copyOf(matching.subList(fromIndex, toIndex)), total);
    }

    private boolean matchesHistoryStatus(ApprovalTicket ticket, String status) {
        return switch (status) {
            case "approved" -> ApprovalStatus.APPROVED.getValue().equalsIgnoreCase(ticket.status());
            case "rejected" -> ApprovalStatus.REJECTED.getValue().equalsIgnoreCase(ticket.status());
            case "expired" -> ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(ticket.status());
            default -> false;
        };
    }

    /** One page of the approval history plus the total count of matching tickets. */
    public record HistoryPage(List<ApprovalTicket> tickets, int total) {
    }

    /**
     * Retrieves all tickets, optionally filtered by status. Retained for the compliance report
     * engine, which counts reported approvals from every resolved ticket.
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

    /** Renders the arguments with DLP masking applied so a ticket never exposes a secret. */
    public static String maskedArguments(ApprovalTicket ticket) {
        if (ticket == null || ticket.arguments() == null) {
            return "{}";
        }
        return DlpScrubber.getInstance().scrub(ticket.arguments()).toString();
    }

    public void clear() {
        List<ActiveTicket> drained;
        synchronized (lifecycleLock) {
            drained = new ArrayList<>(activeTickets.values());
            activeTickets.clear();
            ticketStore.clear();
        }
        // Cancelling a future runs its whenComplete callback, which cancels the ticket; the state
        // is already cleared, so that callback is a no-op.
        for (ActiveTicket active : drained) {
            active.timeoutTask().cancel(true);
            active.future().cancel(true);
        }
    }

    @Override
    public void close() {
        clear();
        notificationDispatcher.close();
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
