package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import dev.aegismcp.gateway.config.ConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Verifies the email approval notification against a fake SMTP relay: the envelope carries the
 * configured sender and recipients, the message names only the opaque ticket token, and a tool
 * argument secret never reaches the body.
 *
 * <p>Anchors: FEAT-006, NFR-023.
 */
class SmtpApprovalNotifierTest {

    private static final String TICKET_ID = TestCredentials.ticketId();
    private static final String PROVIDER_KEY = TestCredentials.providerKey();

    private static ApprovalNotification notification() {
        ApprovalTicket ticket = new ApprovalTicket(
                TICKET_ID,
                "agent-dba",
                "drop_database",
                JsonNodeFactory.instance.objectNode().put("secret", PROVIDER_KEY),
                91.0,
                ApprovalStatus.PENDING.getValue(),
                "2026-11-23T10:00:00Z",
                "2026-11-23T10:05:00Z",
                null, null, "pol_db", "Drop the staging schema", null
        );
        return ApprovalNotification.from(ticket);
    }

    private static ApprovalNotificationConfig.Email emailConfig(int port, String from) {
        return new ApprovalNotificationConfig.Email(
                "127.0.0.1", port, null, null, from,
                List.of("alice@example.com", "bob@example.com"), false);
    }

    @Test
    @DisplayName("FEAT-006: the email notification is delivered with a masked ticket body")
    void deliversMaskedEmail() throws Exception {
        try (FakeSmtpServer server = new FakeSmtpServer()) {
            SmtpApprovalNotifier notifier = new SmtpApprovalNotifier(
                    emailConfig(server.port(), "approvals@example.com"),
                    URI.create("https://console.example.com"),
                    Duration.ofSeconds(2), Duration.ofSeconds(5));

            notifier.deliver(notification());

            awaitMessage(server);
            assertTrue(server.commands().contains("MAIL FROM:<approvals@example.com>"));
            assertTrue(server.commands().contains("RCPT TO:<alice@example.com>"));
            assertTrue(server.commands().contains("RCPT TO:<bob@example.com>"));

            String message = server.message();
            assertTrue(message.contains("Subject: AegisMCP approval required: " + TICKET_ID));

            String body = decodeBody(message);
            assertTrue(body.contains("drop_database"));
            assertTrue(body.contains("Drop the staging schema"));
            assertTrue(body.contains("https://console.example.com/approvals"));
            assertFalse(body.contains(PROVIDER_KEY),
                    "A tool argument secret must never reach the email body");
        }
    }

    @Test
    @DisplayName("FEAT-006: an address that could inject an SMTP command or header is rejected")
    void rejectsUnsafeAddress() {
        assertThrows(ConfigurationException.class, () -> new SmtpApprovalNotifier(
                emailConfig(25, "approvals@example.com\r\nBcc: attacker@example.com"), null));
    }

    private static void awaitMessage(FakeSmtpServer server) throws InterruptedException {
        for (int i = 0; i < 200 && server.message().isEmpty(); i++) {
            Thread.sleep(10);
        }
        if (server.message().isEmpty()) {
            fail("The fake SMTP relay never received the message body");
        }
    }

    /** Extracts the Base64 body after the header block and decodes it. */
    private static String decodeBody(String message) {
        int separator = message.indexOf("\r\n\r\n");
        if (separator < 0) {
            fail("The message has no header/body separator");
        }
        String encoded = message.substring(separator + 4).replace("\r\n", "");
        return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    /** A loopback SMTP relay that records the conversation for one connection. */
    private static final class FakeSmtpServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private final List<String> commands = Collections.synchronizedList(new ArrayList<>());
        private volatile String message = "";

        private FakeSmtpServer() throws IOException {
            serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            thread = Thread.ofPlatform().daemon(true).name("fake-smtp-", 0).start(this::serve);
        }

        private int port() {
            return serverSocket.getLocalPort();
        }

        private List<String> commands() {
            return commands;
        }

        private String message() {
            return message;
        }

        private void serve() {
            try (Socket socket = serverSocket.accept()) {
                socket.setSoTimeout(5000);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                BufferedWriter out = new BufferedWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

                reply(out, "220 fake ESMTP");
                String line;
                List<String> body = new ArrayList<>();
                boolean inData = false;
                while ((line = in.readLine()) != null) {
                    commands.add(line);
                    if (inData) {
                        if (".".equals(line)) {
                            inData = false;
                            message = String.join("\r\n", body);
                            reply(out, "250 queued");
                        } else {
                            body.add(line);
                        }
                        continue;
                    }
                    String upper = line.toUpperCase(Locale.ROOT);
                    if (upper.startsWith("EHLO")) {
                        out.write("250-fake\r\n250 SIZE 1048576\r\n");
                        out.flush();
                    } else if (upper.equals("DATA")) {
                        inData = true;
                        reply(out, "354 end with a lone dot");
                    } else if (upper.equals("QUIT")) {
                        reply(out, "221 bye");
                        break;
                    } else {
                        reply(out, "250 ok");
                    }
                }
            } catch (IOException e) {
                // The assertions run against the captured conversation; a closed test socket is
                // reported by the missing message rather than by failing this helper thread.
            }
        }

        private static void reply(BufferedWriter out, String text) throws IOException {
            out.write(text);
            out.write("\r\n");
            out.flush();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            thread.interrupt();
        }
    }
}
