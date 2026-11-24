package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-013 coverage for the approval outcome sealed on the record: an approved or rejected interaction
 * repeats the verified reviewer, an expired or unreviewed interaction carries {@code null}, and the
 * query repeats the sealed arguments digest without ever returning the arguments.
 *
 * <p>Anchors: FEAT-006, FEAT-007, C-013, schema.md#AuditBlock.
 */
class AuditRecordsReviewerTest {

    private static final String REVIEWER = "operator@aegis.test";
    private static final String SECRET = "sentinel-deploy-credential";

    private final ObjectMapper mapper = new ObjectMapper();
    private AuditLedger ledger;
    private EmbeddedChannel channel;
    private String approvedDigest;
    private String rejectedDigest;
    private String expiredDigest;
    private String unreviewedDigest;

    @BeforeEach
    void setUp() throws Exception {
        ledger = new AuditLedger(1);

        JsonNode approvedArguments = mapper.readTree("{\"environment\":\"production\",\"token\":\"" + SECRET + "\"}");
        JsonNode rejectedArguments = mapper.readTree("{\"environment\":\"production\",\"force\":true}");
        JsonNode expiredArguments = mapper.readTree("{\"environment\":\"production\",\"window\":\"night\"}");
        JsonNode unreviewedArguments = mapper.readTree("{\"text\":\"hello\"}");

        approvedDigest = ArgumentDigest.of(approvedArguments);
        rejectedDigest = ArgumentDigest.of(rejectedArguments);
        expiredDigest = ArgumentDigest.of(expiredArguments);
        unreviewedDigest = ArgumentDigest.of(unreviewedArguments);

        ledger.appendSync(AuditRecord.create("agent-approved", "deploy_prod", "allow", 0, 1.0,
                "status=200", approvedDigest, REVIEWER));
        ledger.appendSync(AuditRecord.create("agent-rejected", "deploy_prod", "block", 0, 1.0,
                "status=403", rejectedDigest, REVIEWER));
        ledger.appendSync(AuditRecord.create("agent-expired", "deploy_prod", "block", 0, 1.0,
                "status=408", expiredDigest, null));
        ledger.appendSync(AuditRecord.create("agent-unreviewed", "echo", "allow", 0, 1.0,
                "status=200", unreviewedDigest, null));
        ledger.flush();

        AuditRecordsHandler handler = new AuditRecordsHandler(ledger, mapper,
                token -> AuditRecordsHandler.AuditAuthorizer.AuthResult.allow(), Runnable::run);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.close();
        }
        if (ledger != null) {
            ledger.close();
        }
    }

    @Test
    @DisplayName("C-013: an approved record carries the verified reviewer and the sealed arguments digest")
    void approvedRecordCarriesReviewer() throws Exception {
        JsonNode record = queryRecord("/api/v1/audit/records?decision=allow&agentId=agent-approved");

        assertEquals("allow", record.path("decision").asText());
        assertEquals("deploy_prod", record.path("toolName").asText());
        assertEquals(REVIEWER, record.path("reviewedBy").asText());
        assertEquals(approvedDigest, record.path("argumentsHash").asText());
        assertFalse(record.toString().contains(SECRET), "Raw arguments must never be returned");
        assertFalse(record.has("arguments"), "The record must not carry the raw arguments");
    }

    @Test
    @DisplayName("C-013: a rejected record carries the verified reviewer")
    void rejectedRecordCarriesReviewer() throws Exception {
        JsonNode record = queryRecord("/api/v1/audit/records?decision=block&agentId=agent-rejected");

        assertEquals("block", record.path("decision").asText());
        assertEquals(REVIEWER, record.path("reviewedBy").asText());
        assertEquals(rejectedDigest, record.path("argumentsHash").asText());
    }

    @Test
    @DisplayName("C-013: an expired and an unreviewed record stay valid with a null reviewer")
    void automaticRecordsCarryNullReviewer() throws Exception {
        JsonNode expired = queryRecord("/api/v1/audit/records?decision=block&agentId=agent-expired");
        assertEquals("block", expired.path("decision").asText());
        assertTrue(expired.path("reviewedBy").isNull(), "An expired approval has no human reviewer");
        assertEquals(expiredDigest, expired.path("argumentsHash").asText());

        JsonNode unreviewed = queryRecord("/api/v1/audit/records?decision=allow&agentId=agent-unreviewed");
        assertEquals("allow", unreviewed.path("decision").asText());
        assertTrue(unreviewed.path("reviewedBy").isNull(), "A call that needed no approval has no reviewer");
        assertEquals(unreviewedDigest, unreviewed.path("argumentsHash").asText());
    }

    @Test
    @DisplayName("C-013: the returned arguments digest is the sealed digest, not the record summary")
    void argumentsHashIsNotTheSummaryDigest() throws Exception {
        JsonNode record = queryRecord("/api/v1/audit/records?agentId=agent-approved");

        // Regression: the endpoint used to hash the summary text ("status=200") instead of
        // repeating the digest sealed with the decision.
        assertFalse(HashUtils.sha256Hex("status=200").equals(record.path("argumentsHash").asText()),
                "The digest must describe the canonicalized arguments, not the record summary");
        assertEquals(approvedDigest, record.path("argumentsHash").asText());
    }

    @Test
    @DisplayName("C-013: the reviewer and digest appear on every record of a mixed page")
    void everyRecordCarriesBothFields() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records?limit=50");
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode records = body(response).path("records");
        assertEquals(4, records.size());
        long previous = Long.MAX_VALUE;
        for (JsonNode record : records) {
            assertTrue(record.has("argumentsHash"), "Every record must carry an argumentsHash");
            assertEquals(64, record.path("argumentsHash").asText().length());
            assertTrue(record.has("reviewedBy"), "Every record must carry reviewedBy, even when null");
            long index = record.path("blockIndex").asLong();
            assertTrue(index < previous, "Records remain ordered by blockIndex descending");
            previous = index;
        }
        response.release();
    }

    private JsonNode queryRecord(String uri) throws Exception {
        FullHttpResponse response = sendGet(uri);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        JsonNode body = body(response);
        assertEquals(1, body.path("total").asInt());
        response.release();
        return body.path("records").get(0);
    }

    private FullHttpResponse sendGet(String uri) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.GET, uri, Unpooled.EMPTY_BUFFER);
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer auditor-token");
        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode body(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(new String(bytes, StandardCharsets.UTF_8));
    }
}
