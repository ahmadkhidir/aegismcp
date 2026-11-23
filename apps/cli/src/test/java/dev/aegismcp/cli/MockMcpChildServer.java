package dev.aegismcp.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Lightweight mock MCP child server process used for testing stdio proxying hermetically.
 * Anchors: FEAT-003.
 */
public class MockMcpChildServer {

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "exit-immediately".equals(args[0])) {
            int code = args.length > 1 ? Integer.parseInt(args[1]) : 0;
            System.exit(code);
            return;
        }

        if (args.length > 0 && "sleep-forever".equals(args[0])) {
            sleepForever();
            return;
        }

        if (args.length > 0 && "flood".equals(args[0])) {
            int bytesPerStream = args.length > 1 ? Integer.parseInt(args[1]) : 256 * 1024;
            flood(bytesPerStream);
            return;
        }

        if (args.length > 0 && "spawn-grandchild".equals(args[0])) {
            spawnGrandchildAndServe();
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
                    // Response containing sensitive AWS access key to test DLP scrubbing
                    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":\"Access key is "
                            + TestCredential.awsAccessKey() + "\"}}");
                    System.out.flush();
                } else {
                    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"echo\":\"ok\"}}");
                    System.out.flush();
                }
            }
        }
    }

    /** Writes more than a pipe buffer to both streams so a single-threaded drain would deadlock. */
    private static void flood(int bytesPerStream) {
        String payload = "x".repeat(120);
        int lines = Math.max(1, bytesPerStream / (payload.length() + 1));
        for (int i = 0; i < lines; i++) {
            System.out.println("OUT " + i + " " + payload);
            System.err.println("ERR " + i + " " + payload);
        }
        System.out.flush();
        System.err.flush();
    }

    /** Spawns a long-lived grandchild, announces its PID, then serves until the parent closes input. */
    private static void spawnGrandchildAndServe() throws Exception {
        String javaBin = ProcessHandle.current().info().command()
                .orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");
        Process grandchild = new ProcessBuilder(
                javaBin, "-cp", classPath, MockMcpChildServer.class.getName(), "sleep-forever")
                .start();

        System.out.println("GRANDCHILD_PID=" + grandchild.pid());
        System.out.flush();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            while (reader.readLine() != null) {
                // Keep the session open; the parent decides when it ends.
            }
        } finally {
            grandchild.destroy();
        }
    }

    private static void sleepForever() throws InterruptedException {
        while (true) {
            Thread.sleep(1_000L);
        }
    }
}
