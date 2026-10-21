package dev.aegismcp.e2e;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Mock MCP child server process for E2E testing of aegis-cli stdio proxy wrapping.
 * Anchors: FEAT-003, FEAT-005.
 */
public class E2EMockMcpChildServer {

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "exit-immediately".equals(args[0])) {
            int code = args.length > 1 ? Integer.parseInt(args[1]) : 0;
            System.exit(code);
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }

                if (line.contains("exit_with_code")) {
                    int code = 0;
                    if (line.contains("\"code\":")) {
                        String sub = line.substring(line.indexOf("\"code\":") + 7);
                        sub = sub.replaceAll("[^0-9]", "");
                        if (!sub.isEmpty()) {
                            code = Integer.parseInt(sub);
                        }
                    }
                    System.exit(code);
                    return;
                }

                if (line.contains("\"method\":\"initialize\"")) {
                    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{}}}");
                    System.out.flush();
                } else if (line.contains("\"name\":\"read_file\"")) {
                    // Response containing sensitive AWS access key to verify DLP scrubbing via wrap
                    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":\"Access key is AKIAIOSFODNN7EXAMPLE\"}}");
                    System.out.flush();
                } else {
                    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"echo\":\"ok\"}}");
                    System.out.flush();
                }
            }
        }
    }
}
