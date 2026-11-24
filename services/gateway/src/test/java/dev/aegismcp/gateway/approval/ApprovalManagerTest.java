package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying ApprovalManager behavior, lifecycle, timeout scheduling, and policy integration.
 * Anchors: FEAT-006, C-003, C-004, NFR-001.
 */
class ApprovalManagerTest {

    private static final String PROVIDER_KEY = TestCredentials.providerKey();

    private final ObjectMapper mapper = new ObjectMapper();
    private ApprovalManager approvalManager;

    @BeforeEach
    void setUp() {
        approvalManager = new ApprovalManager(Duration.ofSeconds(2), ApprovalNotificationConfig.none());
    }

    @AfterEach
    void tearDown() {
        if (approvalManager != null) {
            approvalManager.close();
        }
    }

    private SecurityContext createContext(String agentId) {
        AgentIdentity identity = new AgentIdentity(agentId, null, "test-token", true);
        return SecurityContext.of(identity, new InetSocketAddress("127.0.0.1", 54321));
    }

    @Test
    @DisplayName("FEAT-006 / C-003: Creating approval ticket suspends async future and registers ticket in store")
    void testCreateAndSuspendTicket() {
        ObjectNode args = mapper.createObjectNode();
        args.put("database", "production_master");

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-007",
                "drop_database",
                args,
                95.0,
                "pol_strict",
                Duration.ofMinutes(5)
        );

        assertNotNull(future);
        assertFalse(future.isDone(), "Future should be suspended awaiting human review");

        List<ApprovalTicket> tickets = approvalManager.getTickets("pending");
        assertEquals(1, tickets.size());

        ApprovalTicket ticket = tickets.get(0);
        assertEquals("agent-007", ticket.agentId());
        assertEquals("drop_database", ticket.toolName());
        assertEquals("pending", ticket.status());
        assertEquals(95.0, ticket.riskScore());
    }

    @Test
    @DisplayName("FEAT-006 / C-004: Operator APPROVE decision resumes suspended future with InterceptionVerdict.allow")
    void testOperatorApprovalResumesFuture() throws ExecutionException, InterruptedException, TimeoutException {
        ObjectNode args = mapper.createObjectNode();
        args.put("amount", 50000);

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-finance",
                "wire_transfer",
                args,
                88.0,
                "pol_finance_v1",
                Duration.ofMinutes(5)
        );

        List<ApprovalTicket> tickets = approvalManager.getTickets("pending");
        assertEquals(1, tickets.size());
        String ticketId = tickets.get(0).id();

        ApprovalTicket response = approvalManager.approve(ticketId, "ciso_reviewer");

        assertNotNull(response);
        assertEquals(ticketId, response.id());
        assertEquals("approved", response.status());
        assertNotNull(response.processedAt());

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict, "Approved request must yield Allow verdict");
        assertEquals("ciso_reviewer", verdict.reviewedBy(),
                "The verified reviewer must travel on the verdict to the terminal audit record");

        Optional<ApprovalTicket> updatedOpt = approvalManager.getTicket(ticketId);
        assertTrue(updatedOpt.isPresent());
        ApprovalTicket updated = updatedOpt.get();
        assertEquals("approved", updated.status());
        assertEquals("ciso_reviewer", updated.reviewer());
    }

    @Test
    @DisplayName("FEAT-006 / C-001: Operator REJECT decision fails the call with -32002 APPROVAL_DENIED (HTTP 403)")
    void testOperatorRejectionFailsWithApprovalDenied() throws ExecutionException, InterruptedException, TimeoutException {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "DROP DATABASE users;");

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-dba",
                "execute_sql",
                args,
                99.0,
                "pol_db_guard",
                Duration.ofMinutes(5)
        );

        String ticketId = approvalManager.getTickets("pending").get(0).id();

        ApprovalTicket response = approvalManager.reject(
                ticketId,
                "lead_dba",
                "Prohibited operation on production cluster"
        );

        assertEquals("rejected", response.status());

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;

        assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, block.error().code());
        assertEquals(JsonRpcError.MACHINE_APPROVAL_DENIED, block.error().machineCode());
        assertTrue(block.error().message().contains("Prohibited operation on production cluster"));
        assertEquals(io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN, block.error().toHttpStatus());
        assertEquals("lead_dba", block.reviewedBy(),
                "The rejecting reviewer must travel on the verdict to the terminal audit record");

        ApprovalTicket updated = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("rejected", updated.status());
        assertEquals("lead_dba", updated.reviewer());
        assertEquals("Prohibited operation on production cluster", updated.decisionReason());
    }

    @Test
    @DisplayName("FEAT-006: Timeout auto-rejection completes future with Approval Timed Out (-32002 -> HTTP 408)")
    void testTimeoutAutoRejection() throws ExecutionException, InterruptedException, TimeoutException {
        // Short TTL for deterministic test execution
        ApprovalManager quickTimeoutManager = new ApprovalManager(Duration.ofMillis(200), ApprovalNotificationConfig.none());
        try {
            CompletableFuture<InterceptionVerdict> future = quickTimeoutManager.createAndSuspendTicket(
                    "agent-cron",
                    "scale_cluster",
                    mapper.createObjectNode(),
                    75.0,
                    "pol_infra",
                    Duration.ofMillis(200)
            );

            InterceptionVerdict verdict = future.get(2, TimeUnit.SECONDS);
            assertInstanceOf(InterceptionVerdict.Block.class, verdict);
            InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;

            assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, block.error().code());
            assertEquals(io.netty.handler.codec.http.HttpResponseStatus.REQUEST_TIMEOUT, block.error().toHttpStatus());
            assertTrue(block.error().message().contains("Approval request timed out"));
            assertNull(block.reviewedBy(), "An automatic expiry has no human reviewer to seal");

            List<ApprovalTicket> timedOutTickets = quickTimeoutManager.getTickets("timed_out");
            assertEquals(1, timedOutTickets.size());
            assertEquals("timed_out", timedOutTickets.get(0).status());
        } finally {
            quickTimeoutManager.close();
        }
    }

    @Test
    @DisplayName("C-004: Idempotency check prevents resolving already resolved ticket (HTTP 400)")
    void testIdempotencyCannotResolveAlreadyResolvedTicket() {
        approvalManager.createAndSuspendTicket(
                "agent-test",
                "restart_service",
                mapper.createObjectNode(),
                50.0,
                "pol_ops",
                Duration.ofMinutes(5)
        );

        String ticketId = approvalManager.getTickets("pending").get(0).id();

        // First resolution: approve
        approvalManager.approve(ticketId, "ops_admin");

        // Second resolution attempt must fail with TicketAlreadyResolvedException
        assertThrows(ApprovalException.TicketAlreadyResolvedException.class, () -> {
            approvalManager.reject(ticketId, "secops", "Late reject");
        });
    }

    @Test
    @DisplayName("C-004: Submitting decision on non-existent or expired ticket throws TicketNotFoundException (HTTP 404)")
    void testCannotResolveNonExistentOrExpiredTicket() {
        assertThrows(ApprovalException.TicketNotFoundException.class, () -> {
            approvalManager.approve("appr_non_existent", "admin");
        });
    }

    @Test
    @DisplayName("C-003: Ticket listing with status filtering returns only matching status")
    void testListingWithStatusFiltering() {
        approvalManager.createAndSuspendTicket("agent-1", "tool_a", mapper.createObjectNode(), 50.0, "pol", Duration.ofMinutes(5));
        approvalManager.createAndSuspendTicket("agent-2", "tool_b", mapper.createObjectNode(), 60.0, "pol", Duration.ofMinutes(5));
        approvalManager.createAndSuspendTicket("agent-3", "tool_c", mapper.createObjectNode(), 70.0, "pol", Duration.ofMinutes(5));

        List<ApprovalTicket> pendingTickets = approvalManager.getTickets("pending");
        assertEquals(3, pendingTickets.size());

        String id1 = pendingTickets.get(0).id();
        String id2 = pendingTickets.get(1).id();

        approvalManager.approve(id1, "rev1");
        approvalManager.reject(id2, "rev2", "deny");

        assertEquals(1, approvalManager.getTickets("pending").size());
        assertEquals(1, approvalManager.getTickets("approved").size());
        assertEquals(1, approvalManager.getTickets("rejected").size());
        assertEquals(3, approvalManager.getTickets(null).size());
    }

    @Test
    @DisplayName("FEAT-006: Agent cancellation / client disconnect cancels pending approval ticket")
    void testAgentDisconnectCancelsPendingTicket() {
        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-dc",
                "long_running_migration",
                mapper.createObjectNode(),
                90.0,
                "pol_db",
                Duration.ofMinutes(5)
        );

        assertEquals(1, approvalManager.getActiveTicketCount());

        // Simulate agent disconnecting / future cancelled
        future.cancel(true);

        assertEquals(0, approvalManager.getActiveTicketCount());
        List<ApprovalTicket> tickets = approvalManager.getTickets("rejected");
        assertEquals(1, tickets.size());
        assertTrue(tickets.get(0).decisionReason().contains("cancelled"));
    }

    @Test
    @DisplayName("FEAT-002 / FEAT-006: DeclarativePolicyInterceptor wires seamlessly with ApprovalManager on REQUIRE_APPROVAL")
    void testIntegrationWithDeclarativePolicyInterceptor() throws Exception {
        String yaml = """
                id: pol_hitl_test
                name: HITL Policy
                version: 1.0.0
                rules:
                  - id: rule_critical
                    tool: delete_all_data
                    action: require_approval
                """;

        SecurityPolicy policy = SecurityPolicy.of("pol_hitl_test", "HITL Policy", "1.0.0", yaml, "sha-hitl");
        PolicyCache cache = new PolicyCache();
        cache.putPolicy(policy);
        PolicyEvaluator evaluator = new PolicyEvaluator(cache);

        DeclarativePolicyInterceptor interceptor = new DeclarativePolicyInterceptor(evaluator, approvalManager);
        // The shipped chain keeps running after policy (anomaly, then the proxy); the reviewer the
        // approval decision carries must survive to the terminal audit record (FEAT-006, C-013).
        ToolCallInterceptor chain = ToolCallInterceptor.chain(interceptor,
                (ctx, req) -> CompletableFuture.completedFuture(InterceptionVerdict.allow()));

        SecurityContext context = createContext("agent-dba");
        ObjectNode params = mapper.createObjectNode();
        params.put("name", "delete_all_data");

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-delete-1"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = chain.intercept(context, request);
        assertNotNull(future);
        assertFalse(future.isDone());

        List<ApprovalTicket> pending = approvalManager.getTickets("pending");
        assertEquals(1, pending.size());
        assertEquals("delete_all_data", pending.get(0).toolName());

        // Approve ticket
        approvalManager.approve(pending.get(0).id(), "lead_admin");

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
        assertEquals("lead_admin", verdict.reviewedBy(),
                "A downstream stage must not erase the reviewer the approval decision sealed");
    }

    @Test
    @DisplayName("FEAT-006: a ticket token is appr_ followed by 26 base32 characters and never repeats")
    void ticketTokenMatchesTheSpecifiedShape() {
        Set<String> issued = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            String token = ApprovalManager.newTicketId();
            assertTrue(token.matches("^appr_[A-Z2-7]{26}$"), "Unexpected token shape: " + token);
            assertTrue(issued.add(token), "Ticket tokens must not repeat");
        }
    }

    @Test
    @DisplayName("FEAT-006: two simultaneous decisions apply exactly one and the loser reports the recorded outcome")
    void concurrentDecisionsApplyOnce() throws Exception {
        approvalManager.createAndSuspendTicket("agent-race", "delete_everything",
                mapper.createObjectNode(), 99.0, "pol_db", Duration.ofMinutes(5));
        String ticketId = approvalManager.getTickets("pending").get(0).id();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<String>> results = new ArrayList<>();
            for (String reviewer : List.of("reviewer-a", "reviewer-b")) {
                results.add(pool.submit(() -> {
                    start.await();
                    try {
                        approvalManager.approve(ticketId, reviewer);
                        return "won:" + reviewer;
                    } catch (ApprovalException.TicketAlreadyResolvedException e) {
                        return "lost:" + reviewer;
                    }
                }));
            }
            start.countDown();

            List<String> outcomes = new ArrayList<>();
            for (Future<String> result : results) {
                outcomes.add(result.get(5, TimeUnit.SECONDS));
            }

            assertEquals(1, outcomes.stream().filter(outcome -> outcome.startsWith("won:")).count());
            assertEquals(1, outcomes.stream().filter(outcome -> outcome.startsWith("lost:")).count());

            String winner = outcomes.stream().filter(outcome -> outcome.startsWith("won:"))
                    .findFirst().orElseThrow().substring(4);
            ApprovalTicket resolved = approvalManager.getTicket(ticketId).orElseThrow();
            assertEquals("approved", resolved.status());
            assertEquals(winner, resolved.reviewer());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("FEAT-006: suspending a call dispatches one masked notification and keeps the ticket pending")
    void suspendingCallDispatchesMaskedNotification() {
        List<ApprovalNotification> delivered = new ArrayList<>();
        ApprovalNotificationChannel recording = new ApprovalNotificationChannel() {
            @Override
            public String name() {
                return "recorder";
            }

            @Override
            public void deliver(ApprovalNotification notification) {
                delivered.add(notification);
            }
        };
        ApprovalNotificationDispatcher dispatcher = new ApprovalNotificationDispatcher(
                List.of(recording), 1, Duration.ZERO, Runnable::run, false, duration -> {
                });

        try (ApprovalManager manager = new ApprovalManager(
                Duration.ofMinutes(5), ApprovalNotificationConfig.none(), dispatcher)) {
            ObjectNode args = mapper.createObjectNode();
            args.put("secret", PROVIDER_KEY);

            manager.createAndSuspendTicket("agent-pay", "charge_card", args, 80.0, "pol_pay",
                    "Refund the disputed charge", Duration.ofMinutes(5));

            assertEquals(1, delivered.size());
            ApprovalNotification notification = delivered.get(0);
            assertFalse(notification.argumentsPayload().contains(PROVIDER_KEY),
                    "Notification arguments must be DLP-masked");
            assertEquals("Refund the disputed charge", notification.agentIntent());
            assertEquals("pending", manager.getTicket(notification.ticketId()).orElseThrow().status());
            assertTrue(dispatcher.recordFor(notification.ticketId(), "recorder").orElseThrow().delivered(),
                    "The delivery outcome must be recorded");
        }
    }
}
