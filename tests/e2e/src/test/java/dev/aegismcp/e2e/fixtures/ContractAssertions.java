package dev.aegismcp.e2e.fixtures;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.http.HttpResponse;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Assertions every contract class shares. They encode only what the contract files state.
 */
public final class ContractAssertions {

    private ContractAssertions() {
    }

    public static void assertStatus(int expected, HttpResponse<String> response) {
        assertEquals(expected, response.statusCode(),
                () -> "Expected HTTP " + expected + " but got " + response.statusCode()
                        + " with body: " + response.body());
    }

    public static JsonNode assertRpcError(
            HttpResponse<String> response,
            int expectedHttpStatus,
            int expectedCode,
            String expectedMachineCode
    ) throws Exception {
        assertStatus(expectedHttpStatus, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.has("error"), () -> "Expected a JSON-RPC error body, got: " + response.body());
        assertEquals("2.0", body.path("jsonrpc").asText(), "JSON-RPC version must be 2.0");
        assertEquals(expectedCode, body.path("error").path("code").asInt(),
                () -> "Unexpected JSON-RPC error code in: " + response.body());
        assertEquals(expectedMachineCode, body.path("error").path("data").path("code").asText(),
                () -> "Unexpected machine code in: " + response.body());
        return body;
    }

    public static JsonNode assertRpcError(HttpResponse<String> response, int expectedHttpStatus, int expectedCode)
            throws Exception {
        assertStatus(expectedHttpStatus, response);
        JsonNode body = GatewayHarness.json(response);
        assertEquals(expectedCode, body.path("error").path("code").asInt(),
                () -> "Unexpected JSON-RPC error code in: " + response.body());
        return body;
    }

    public static JsonNode assertError(HttpResponse<String> response, int expectedHttpStatus, String expectedError)
            throws Exception {
        assertStatus(expectedHttpStatus, response);
        JsonNode body = GatewayHarness.json(response);
        assertEquals(expectedError, body.path("error").asText(),
                () -> "Unexpected error body: " + response.body());
        return body;
    }

    public static void assertIso8601(String value, String field) {
        assertNotNull(value, field + " must be present");
        assertFalse(value.isBlank(), field + " must not be blank");
        assertNotNull(Instant.parse(value), field + " must be an ISO-8601 instant");
    }

    public static void assertNoInternalDetail(HttpResponse<String> response) {
        String body = response.body() != null ? response.body() : "";
        assertFalse(body.contains("Exception"), () -> "Error body leaked exception detail: " + body);
        assertFalse(body.contains("at dev.aegismcp"), () -> "Error body leaked a stack frame: " + body);
        assertFalse(body.contains("java."), () -> "Error body leaked a Java type: " + body);
    }
}
