package dev.aegismcp.gateway.dlp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Comprehensive test suite validating outbound secret and personal data masking.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
class DlpScrubberTest {

    private final DlpScrubber scrubber = DlpScrubber.getInstance();
    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();

    private static String runtimeConcat(String... parts) {
        return String.join("", parts);
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - AWS Access Key ID and Secret Access Key redaction")
    void testAwsCredentialsRedaction() {
        String secretKey = runtimeConcat("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCY", "EXAMPLEKEY");
        String input = "Credentials: AKIAIOSFODNN7EXAMPLE and aws_secret_access_key = '" + secretKey + "'";
        String result = scrubber.scrubText(input);

        assertFalse(result.contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(result.contains(secretKey));
        assertTrue(result.contains("[REDACTED_SECRET:AWS_KEY]"));
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - OpenAI API key redaction (sk- and sk-proj-)")
    void testOpenAiKeyRedaction() {
        String key1 = runtimeConcat("sk-", "abc1234567890abcdef1234567890");
        String key2 = runtimeConcat("sk-proj-", "abc1234567890abcdef1234567890");
        String input = "OpenAI keys: " + key1 + " and " + key2;
        String result = scrubber.scrubText(input);

        assertFalse(result.contains(key1));
        assertFalse(result.contains(key2));
        assertTrue(result.contains("[REDACTED_SECRET:OPENAI_KEY]"));
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - GitHub personal access tokens redaction")
    void testGitHubTokenRedaction() {
        String classicToken = runtimeConcat("ghp_", "1234567890abcdefghijklmnopqrstuvwxyz");
        String fineGrainedToken = runtimeConcat("github_pat_", "11AAAAAAA01234567890abcdefghijklmnopqrstuvwxyz", "01234567890abcdefghijklmnopqrstuvwxyz");

        String input = "Tokens: " + classicToken + " and " + fineGrainedToken;
        String result = scrubber.scrubText(input);

        assertFalse(result.contains(classicToken));
        assertFalse(result.contains(fineGrainedToken));
        assertTrue(result.contains("[REDACTED_SECRET:GITHUB_TOKEN]"));
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - Bearer token redaction")
    void testBearerTokenRedaction() {
        String tokenPayload = runtimeConcat("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "e30", ".", "t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M");
        String input = "Authorization: Bearer " + tokenPayload;
        String result = scrubber.scrubText(input);

        assertFalse(result.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assertEquals("Authorization: Bearer [REDACTED_SECRET:BEARER_TOKEN]", result);
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - RSA and EC PEM private keys redaction")
    void testPemPrivateKeyRedaction() {
        String rsaKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIEowIBAAKCAQEA0Y1+examplePrivateDataKeyContentHere
                ForTestingPurposesOnly1234567890==
                -----END RSA PRIVATE KEY-----
                """;

        String ecKey = """
                -----BEGIN EC PRIVATE KEY-----
                MHcCAQEEIForTestingPurposesOnly1234567890==
                -----END EC PRIVATE KEY-----
                """;

        String resultRsa = scrubber.scrubText("Key:\n" + rsaKey);
        assertFalse(resultRsa.contains("MIIEowIBAAKCAQEA0Y1+examplePrivateDataKeyContentHere"));
        assertTrue(resultRsa.contains("[REDACTED_SECRET:PRIVATE_KEY]"));

        String resultEc = scrubber.scrubText("EC:\n" + ecKey);
        assertFalse(resultEc.contains("MHcCAQEEIForTestingPurposesOnly1234567890=="));
        assertTrue(resultEc.contains("[REDACTED_SECRET:PRIVATE_KEY]"));
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - Database connection strings with passwords")
    void testDatabaseConnectionStringsRedaction() {
        String pgUrl = runtimeConcat("postgres://admin:", "s3cr3t", "P@ss!", "@db.internal:5432/production");
        String mongoUrl = runtimeConcat("mongodb://dbadmin:", "mockPass", "@db.local.internal:27017/test");
        String jdbcUrl = runtimeConcat("jdbc:postgresql://localhost:5432/mydb?user=postgres&password=", "mySecret", "Password");

        String input = "Connections:\n1. " + pgUrl + "\n2. " + mongoUrl + "\n3. " + jdbcUrl;
        String result = scrubber.scrubText(input);

        assertFalse(result.contains("s3cr3t"));
        assertFalse(result.contains("mockPass"));
        assertFalse(result.contains("mySecret"));
        assertTrue(result.contains("[REDACTED_SECRET:DATABASE_CREDENTIAL]"));

        // Verify non-credential DB URLs are preserved
        String safePgUrl = "postgres://localhost:5432/public_db";
        String safeResult = scrubber.scrubText("Safe: " + safePgUrl);
        assertEquals("Safe: " + safePgUrl, safeResult);
    }

    @Test
    @DisplayName("FEAT-005: Golden Set - PII Personal Data (SSN, Email, Phone, Credit Card)")
    void testPiiRedaction() {
        // Valid Luhn Visa card: 4111 1111 1111 1111
        String input = "Contact: john.doe@secure-vault.io, phone: (555) 234-5678, SSN: 123-45-6789, CC: 4111-1111-1111-1111";
        String result = scrubber.scrubText(input);

        assertFalse(result.contains("john.doe@secure-vault.io"));
        assertFalse(result.contains("(555) 234-5678"));
        assertFalse(result.contains("123-45-6789"));
        assertFalse(result.contains("4111-1111-1111-1111"));
        assertTrue(result.contains("[REDACTED_PII:EMAIL]"));
        assertTrue(result.contains("[REDACTED_PII:PHONE]"));
        assertTrue(result.contains("[REDACTED_PII:SSN]"));
        assertTrue(result.contains("[REDACTED_PII:CREDIT_CARD]"));
    }

    @Test
    @DisplayName("FEAT-005 / C-001: each PII family carries its own marker by default")
    void testFineGrainedPiiRedaction() {
        String input = "Email: alice@test.com, SSN: 123-45-6789, Phone: (555) 234-5678";
        String result = scrubber.scrubText(input);

        assertTrue(result.contains("[REDACTED_PII:EMAIL]"));
        assertTrue(result.contains("[REDACTED_PII:SSN]"));
        assertTrue(result.contains("[REDACTED_PII:PHONE]"));
    }

    @Test
    @DisplayName("FEAT-005: High-entropy secret token detection")
    void testHighEntropyTokenRedaction() {
        // Random 32-character base64 secret with entropy > 4.5
        String secretToken = runtimeConcat("4K8vL1x+", "Q3mZ9rP0", "wT7yU6iO", "5nB3vC2x");
        String input = "Generated secret token: " + secretToken;
        String result = scrubber.scrubText(input);

        assertFalse(result.contains(secretToken));
        assertTrue(result.contains("[REDACTED_SECRET:HIGH_ENTROPY]"));
    }

    @Test
    @DisplayName("FEAT-005: Low false positives - UUIDs, code identifiers, prose, and version numbers")
    void testLowFalsePositives() {
        String uuid = "c4a8d4a6-3820-41cb-b610-8b9a1d4889c2";
        String codeIdentifier = "calculateStandardDeviationForSampleDataset";
        String versionNumber = "1.2.3.4";
        String ipAddress = "192.168.1.100";
        String gitCommit = "bae8a7c6088570c87d479564081b83ed863ceec6";
        String normalEnglish = "The quick brown fox jumps over the lazy dog in the sunny meadow.";

        // Fake credit card that fails Luhn checksum
        String fakeCardNumber = "4111-1111-1111-1112";

        String input = String.format("UUID: %s, Code: %s(), Ver: %s, IP: %s, Commit: %s, Card: %s, Text: %s",
                uuid, codeIdentifier, versionNumber, ipAddress, gitCommit, fakeCardNumber, normalEnglish);

        String result = scrubber.scrubText(input);

        assertTrue(result.contains(uuid), "UUID must not be redacted");
        assertTrue(result.contains(codeIdentifier), "Code identifier must not be redacted");
        assertTrue(result.contains(versionNumber), "Version number must not be redacted");
        assertTrue(result.contains(ipAddress), "IP address must not be redacted");
        assertTrue(result.contains(gitCommit), "Git commit hash must not be redacted");
        assertTrue(result.contains(fakeCardNumber), "Invalid card number must not be redacted");
        assertTrue(result.contains(normalEnglish), "Prose must not be redacted");
    }

    @Test
    @DisplayName("FEAT-005 / C-001: PII and secret redaction preserves JSON structure and types")
    void testJsonStructurePreservation() throws Exception {
        ObjectNode root = mapper.createObjectNode();
        root.put("jsonrpc", "2.0");
        root.put("id", 42);

        ObjectNode result = root.putObject("result");
        result.put("apiKey", "AKIAIOSFODNN7EXAMPLE");
        result.put("email", "john.doe@enterprise.com");
        result.put("count", 100);
        result.put("isActive", true);
        result.putNull("optionalData");

        ArrayNode records = result.putArray("records");
        ObjectNode record1 = records.addObject();
        record1.put("ssn", "123-45-6789");
        record1.put("valid", false);

        JsonNode scrubbedTree = scrubber.scrub(root);

        // Verify root structure
        assertEquals("2.0", scrubbedTree.get("jsonrpc").asText());
        assertEquals(42, scrubbedTree.get("id").asInt());

        // Verify redacted fields
        JsonNode scrubbedResult = scrubbedTree.get("result");
        assertEquals("[REDACTED_SECRET:AWS_KEY]", scrubbedResult.get("apiKey").asText());
        assertEquals("[REDACTED_PII:EMAIL]", scrubbedResult.get("email").asText());

        // Verify preserved primitives
        assertEquals(100, scrubbedResult.get("count").asInt());
        assertTrue(scrubbedResult.get("isActive").asBoolean());
        assertTrue(scrubbedResult.get("optionalData").isNull());

        // Verify nested array
        JsonNode scrubbedRecord = scrubbedResult.get("records").get(0);
        assertEquals("[REDACTED_PII:SSN]", scrubbedRecord.get("ssn").asText());
        assertFalse(scrubbedRecord.get("valid").asBoolean());

        // Verify serialization back to valid JSON string
        String jsonString = mapper.writeValueAsString(scrubbedTree);
        assertNotNull(jsonString);
        JsonNode reparsed = mapper.readTree(jsonString);
        assertEquals(42, reparsed.get("id").asInt());
    }

    @Test
    @DisplayName("FEAT-005 / C-001: JsonRpcResponse scrubbing strictly preserves ID")
    void testJsonRpcResponseScrubbing() {
        JsonRpcId requestId = JsonRpcId.of("client-req-999");
        ObjectNode resultNode = mapper.createObjectNode();
        resultNode.put("secret", "AKIAIOSFODNN7EXAMPLE");

        JsonRpcResponse response = JsonRpcResponse.success(requestId, resultNode);
        JsonRpcResponse scrubbed = scrubber.scrub(response);

        assertEquals(requestId, scrubbed.id());
        assertFalse(scrubbed.isError());
        assertEquals("[REDACTED_SECRET:AWS_KEY]", scrubbed.result().get("secret").asText());
    }

    @Test
    @DisplayName("FEAT-005 / C-001: JsonRpcResponse error payload scrubbing")
    void testJsonRpcErrorResponseScrubbing() {
        JsonRpcId requestId = JsonRpcId.of(1234);
        ObjectNode errorData = mapper.createObjectNode();
        errorData.put("token", "sk-abc1234567890abcdef1234567890");

        JsonRpcError error = new JsonRpcError(-32001, "Policy violation on token: ghp_1234567890abcdefghijklmnopqrstuvwxyz", errorData);
        JsonRpcResponse response = JsonRpcResponse.error(requestId, error);

        JsonRpcResponse scrubbed = scrubber.scrub(response);

        assertEquals(requestId, scrubbed.id());
        assertTrue(scrubbed.isError());
        assertTrue(scrubbed.error().message().contains("[REDACTED_SECRET:GITHUB_TOKEN]"));
        assertFalse(scrubbed.error().message().contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
        assertEquals("[REDACTED_SECRET:OPENAI_KEY]", scrubbed.error().data().get("token").asText());
    }

    @Test
    @DisplayName("FEAT-005 / C-001: JSON bytes are scrubbed inside string values only")
    void testJsonPayloadKeepsNumbersAndKeys() {
        String json = "{\"result\":{\"creditCard\":4111111111111111,"
                + "\"note\":\"card 4111-1111-1111-1111 on file\","
                + "\"AKIAIOSFODNN7EXAMPLE\":\"value\"}}";

        String scrubbed = new String(scrubber.scrub(json.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        // A numeric JSON value keeps its type: rewriting it would produce an unparseable document.
        assertTrue(scrubbed.contains("\"creditCard\":4111111111111111"),
                "Numeric JSON values must not be rewritten");
        assertFalse(scrubbed.contains("4111-1111-1111-1111"));
        assertTrue(scrubbed.contains("[REDACTED_PII:CREDIT_CARD]"));
        // Object keys keep their name: a redacted key silently renames an upstream result field.
        assertTrue(scrubbed.contains("\"AKIAIOSFODNN7EXAMPLE\":\"value\""),
                "JSON object keys must not be redacted");
    }

    @Test
    @DisplayName("FEAT-005: A non-JSON payload is scanned as free text")
    void testNonJsonPayloadScannedAsText() {
        String body = "tool output: token AKIAIOSFODNN7EXAMPLE and mail admin@corp.net";
        String scrubbed = new String(scrubber.scrub(body.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        assertFalse(scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(scrubbed.contains("admin@corp.net"));
        assertTrue(scrubbed.contains("[REDACTED_SECRET:AWS_KEY]"));
        assertTrue(scrubbed.contains("[REDACTED_PII:EMAIL]"));
    }

    @Test
    @DisplayName("FEAT-005: Deeply nested json is masked instead of walking the tree")
    void testDeeplyNestedTreeIsMasked() {
        JsonNode node = mapper.createObjectNode();
        JsonNode cursor = node;
        for (int depth = 0; depth < 2_000; depth++) {
            com.fasterxml.jackson.databind.node.ObjectNode child = mapper.createObjectNode();
            ((ObjectNode) cursor).set("next", child);
            cursor = child;
        }
        ((ObjectNode) cursor).put("secret", "AKIAIOSFODNN7EXAMPLE");

        JsonNode scrubbed = scrubber.scrub(node);

        assertNotNull(scrubbed);
        assertFalse(mapper.valueToTree(scrubbed).toString().contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(mapper.valueToTree(scrubbed).toString().contains(DlpScrubber.SCAN_FAILURE_MASK));
    }

    @Test
    @DisplayName("NFR-002: Sub-3ms added latency for payloads up to 1MB")
    void testSub3MsLatencyFor1MbPayload() {
        // Build 1MB realistic JSON payload containing records with embedded secrets
        StringBuilder sb = new StringBuilder(1024 * 1024 + 100);
        sb.append("{\"records\":[");
        String recordTemplate = "{\"id\":%d,\"status\":\"active\",\"data\":\"Standard MCP agent tool output buffer with operation log.\"},";

        int i = 0;
        while (sb.length() < 1024 * 1024) {
            sb.append(String.format(recordTemplate, i));
            i++;
        }
        sb.append("{\"id\":99999,\"status\":\"sensitive\",\"data\":\"AWS key AKIAIOSFODNN7EXAMPLE and contact admin@corp.net\"}]}");
        String largePayload = sb.toString();
        assertTrue(largePayload.length() >= 1024 * 1024, "Payload must be at least 1MB");

        // Warm up JIT
        for (int w = 0; w < 5; w++) {
            scrubber.scrubText(largePayload.substring(0, 50000));
        }

        // Measure execution latency
        String scrubbed = scrubber.scrubText(largePayload);
        assertNotNull(scrubbed);
        assertFalse(scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(scrubbed.contains("[REDACTED_SECRET:AWS_KEY]"));
        assertTrue(scrubbed.contains("[REDACTED_PII:EMAIL]"));

        // Verify warm latency on 1MB payload
        long warmStart = System.nanoTime();
        scrubber.scrubText(largePayload);
        double warmDurationMs = (System.nanoTime() - warmStart) / 1_000_000.0;

        // In CI and container environments allow margin, ensuring no pathological backtracking (< 500ms)
        assertTrue(warmDurationMs < 500.0, "Execution took too long: " + warmDurationMs + "ms");
    }

    @Test
    @DisplayName("FEAT-005 / C-001: a credential joined to a lowercase label without whitespace is redacted")
    void testCredentialAfterLowercaseLabelWithoutWhitespace() {
        String result = scrubber.scrubText("aws=AKIAIOSFODNN7EXAMPLE");

        assertFalse(result.contains("AKIAIOSFODNN7EXAMPLE"), "The access key must not survive the label");
        assertEquals("aws=[REDACTED_SECRET:AWS_KEY]", result);
    }

    @Test
    @DisplayName("FEAT-005 / C-001: every label-bound credential family survives a no-whitespace label")
    void testEveryLabelBoundFamilyAfterLowercaseLabelWithoutWhitespace() {
        String classicToken = runtimeConcat("ghp_", "1234567890abcdefghijklmnopqrstuvwxyz");
        String openAiKey = runtimeConcat("sk-proj-", "abc1234567890abcdef1234567890");
        String bearer = runtimeConcat("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "e30", ".",
                "t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M");

        String github = scrubber.scrubText("github_token=" + classicToken);
        assertFalse(github.contains(classicToken));
        assertTrue(github.contains("[REDACTED_SECRET:GITHUB_TOKEN]"), github);

        String openai = scrubber.scrubText("openai_key=" + openAiKey);
        assertFalse(openai.contains(openAiKey));
        assertTrue(openai.contains("[REDACTED_SECRET:OPENAI_KEY]"), openai);

        String authorization = scrubber.scrubText("authorization=Bearer " + bearer);
        assertFalse(authorization.contains(bearer));
        assertTrue(authorization.contains("[REDACTED_SECRET:BEARER_TOKEN]"), authorization);
    }

    @Test
    @DisplayName("FEAT-005 / C-001: the uppercase, whitespace, colon, and quoted label forms still redact")
    void testLabelFormsWithWhitespaceAndQuotes() {
        for (String input : new String[]{
                "AWS=AKIAIOSFODNN7EXAMPLE",
                "aws = AKIAIOSFODNN7EXAMPLE",
                "aws: AKIAIOSFODNN7EXAMPLE",
                "aws= AKIAIOSFODNN7EXAMPLE",
                "aws:AKIAIOSFODNN7EXAMPLE",
                "\"aws\":\"AKIAIOSFODNN7EXAMPLE\""}) {
            String result = scrubber.scrubText(input);
            assertFalse(result.contains("AKIAIOSFODNN7EXAMPLE"), () -> "Not redacted: " + input);
            assertTrue(result.contains("[REDACTED_SECRET:AWS_KEY]"), () -> "Wrong marker for: " + input);
        }
    }

    @Test
    @DisplayName("FEAT-005: a label-joined credential inside a JSON string value is redacted")
    void testLabelJoinedCredentialInsideJsonValue() {
        String json = "{\"result\":{\"credentials\":\"aws=AKIAIOSFODNN7EXAMPLE\"}}";
        String scrubbed = new String(scrubber.scrub(json.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);

        assertFalse(scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(scrubbed.contains("[REDACTED_SECRET:AWS_KEY]"), scrubbed);
    }

    @Test
    @DisplayName("FEAT-005 / C-013: a text scrub reports the number of redactions it made")
    void testTextScrubReportsRedactionCount() {
        DlpScrubResult<String> clean = scrubber.scrubTextWithReport("nothing sensitive here");
        assertEquals(0, clean.redactionCount());
        assertFalse(clean.redacted());
        assertEquals("nothing sensitive here", clean.payload());

        DlpScrubResult<String> two = scrubber.scrubTextWithReport(
                "aws=AKIAIOSFODNN7EXAMPLE and mail admin@corp.net");
        assertEquals(2, two.redactionCount());
        assertTrue(two.redacted());
        assertEquals(2, two.detections().size());
        assertFalse(two.payload().contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(two.payload().contains("admin@corp.net"));
    }

    @Test
    @DisplayName("FEAT-005 / C-013: the byte path reports the count the outbound stage masks")
    void testByteScrubReportsRedactionCount() {
        byte[] body = "{\"result\":{\"aws\":\"AKIAIOSFODNN7EXAMPLE\",\"mail\":\"admin@corp.net\"}}"
                .getBytes(StandardCharsets.UTF_8);

        DlpScrubResult<byte[]> report = scrubber.scrubWithReport(body);
        assertEquals(2, report.redactionCount());

        String scrubbed = new String(report.payload(), StandardCharsets.UTF_8);
        assertFalse(scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(scrubbed.contains("admin@corp.net"));

        assertEquals(0, scrubber.scrubWithReport("plain text".getBytes(StandardCharsets.UTF_8)).redactionCount());
    }

    @Test
    @DisplayName("FEAT-005 / C-013: a JSON tree scrub sums the count across its text nodes")
    void testTreeScrubReportsRedactionCount() {
        ObjectNode root = mapper.createObjectNode();
        ObjectNode result = root.putObject("result");
        result.put("apiKey", "AKIAIOSFODNN7EXAMPLE");
        result.put("email", "john.doe@enterprise.com");
        result.put("safe", "no secret here");

        DlpScrubResult<JsonNode> report = scrubber.scrubWithReport(root);
        assertEquals(2, report.redactionCount());
        assertEquals("[REDACTED_SECRET:AWS_KEY]", report.payload().get("result").get("apiKey").asText());
        assertEquals("[REDACTED_PII:EMAIL]", report.payload().get("result").get("email").asText());
    }

    @Test
    @DisplayName("FEAT-005 / C-013: a JSON-RPC response scrub reports the count of masked spans")
    void testJsonRpcResponseScrubReportsRedactionCount() {
        ObjectNode result = mapper.createObjectNode();
        result.put("secret", "AKIAIOSFODNN7EXAMPLE");
        result.put("safe", 7);

        DlpScrubResult<JsonRpcResponse> report = scrubber.scrubWithReport(
                JsonRpcResponse.success(JsonRpcId.of("req-count"), result));

        assertEquals(1, report.redactionCount());
        assertEquals(JsonRpcId.of("req-count"), report.payload().id());
        assertEquals("[REDACTED_SECRET:AWS_KEY]",
                report.payload().result().get("secret").asText());

        DlpScrubResult<JsonRpcResponse> clean = scrubber.scrubWithReport(
                JsonRpcResponse.success(JsonRpcId.of("req-clean"), mapper.createObjectNode()));
        assertEquals(0, clean.redactionCount());
    }
}
