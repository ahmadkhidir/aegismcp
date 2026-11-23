package dev.aegismcp.gateway.approval;

import dev.aegismcp.gateway.config.ConfigurationException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/**
 * Delivers an approval notification to an operator mailbox over SMTP (FEAT-006).
 *
 * <p>Email is a notification channel only: the recipient decides in the Web Console queue, which is
 * why the body carries the ticket identifier and a console link rather than an inline decision. The
 * message is plain text with a Base64 body, the subject names only the opaque ticket token, and
 * every address is rejected if it could break the SMTP command or header grammar. Credentials are
 * sent only after the channel is encrypted; {@code STARTTLS} defaults to enabled.
 *
 * <p>Anchors: FEAT-006, NFR-023.
 */
public final class SmtpApprovalNotifier implements ApprovalNotificationChannel {

    private static final String CHANNEL_NAME = "email";
    private static final String HELO_NAME = "aegismcp";
    private static final int BASE64_LINE_WIDTH = 76;

    private final ApprovalNotificationConfig.Email config;
    private final URI consoleBaseUrl;
    private final Duration connectTimeout;
    private final Duration readTimeout;

    public SmtpApprovalNotifier(ApprovalNotificationConfig.Email config, URI consoleBaseUrl) {
        this(config, consoleBaseUrl, Duration.ofSeconds(5), Duration.ofSeconds(10));
    }

    public SmtpApprovalNotifier(ApprovalNotificationConfig.Email config, URI consoleBaseUrl,
                                Duration connectTimeout, Duration readTimeout) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.consoleBaseUrl = consoleBaseUrl;
        this.connectTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout must not be null");
        this.readTimeout = Objects.requireNonNull(readTimeout, "readTimeout must not be null");
        requireSafeAddress(config.from(), "AEGIS_APPROVAL_EMAIL_FROM");
        config.recipients().forEach(
                recipient -> requireSafeAddress(recipient, "AEGIS_APPROVAL_EMAIL_TO"));
    }

    @Override
    public String name() {
        return CHANNEL_NAME;
    }

    @Override
    public void deliver(ApprovalNotification notification) throws Exception {
        try (SmtpSession session = SmtpSession.open(
                config.smtpHost(), config.smtpPort(),
                connectTimeout.toMillis(), readTimeout.toMillis())) {
            session.expect(220);
            session.sendLine("EHLO " + HELO_NAME);
            session.expectIn(250);
            if (config.startTls()) {
                session.sendLine("STARTTLS");
                session.expect(220);
                session.upgradeToTls(config.smtpHost(), config.smtpPort());
                session.sendLine("EHLO " + HELO_NAME);
                session.expectIn(250);
            }
            if (config.username() != null) {
                session.authenticate(config.username(), config.password());
            }
            session.sendLine("MAIL FROM:<" + config.from() + ">");
            session.expectIn(250);
            for (String recipient : config.recipients()) {
                session.sendLine("RCPT TO:<" + recipient + ">");
                session.expectIn(250, 251);
            }
            session.sendLine("DATA");
            session.expect(354);
            session.writeData(buildMessage(notification));
            session.expectIn(250);
            session.sendLine("QUIT");
            session.expectIn(221);
        }
    }

    /**
     * Builds the RFC 5322 message. The body is Base64 so argument text can never be read as an SMTP
     * command or a header, and the subject carries only the opaque ticket token.
     */
    String buildMessage(ApprovalNotification notification) {
        StringBuilder body = new StringBuilder(notification.asText());
        if (consoleBaseUrl != null) {
            String base = consoleBaseUrl.toString();
            body.append('\n').append('\n')
                    .append("Review pending approvals: ")
                    .append(base.endsWith("/") ? base : base + "/")
                    .append("approvals");
        }

        String encodedBody = Base64.getEncoder()
                .encodeToString(body.toString().getBytes(StandardCharsets.UTF_8));

        StringBuilder message = new StringBuilder();
        message.append("From: ").append(config.from()).append("\r\n")
                .append("To: ").append(String.join(", ", config.recipients())).append("\r\n")
                .append("Subject: AegisMCP approval required: ").append(notification.ticketId())
                .append("\r\n")
                .append("Date: ").append(ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .append("\r\n")
                .append("MIME-Version: 1.0\r\n")
                .append("Content-Type: text/plain; charset=UTF-8\r\n")
                .append("Content-Transfer-Encoding: base64\r\n")
                .append("\r\n");
        for (int i = 0; i < encodedBody.length(); i += BASE64_LINE_WIDTH) {
            message.append(encodedBody, i, Math.min(i + BASE64_LINE_WIDTH, encodedBody.length()))
                    .append("\r\n");
        }
        return message.toString();
    }

    /** A single SMTP conversation; every reply is checked against the expected status family. */
    static final class SmtpSession implements Closeable {
        private Socket socket;
        private BufferedReader reader;
        private Writer writer;

        private SmtpSession(Socket socket) throws IOException {
            this.socket = socket;
            resetStreams();
        }

        static SmtpSession open(String host, int port, long connectTimeoutMs, long readTimeoutMs)
                throws IOException {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(host, port), Math.toIntExact(connectTimeoutMs));
                socket.setSoTimeout(Math.toIntExact(readTimeoutMs));
                return new SmtpSession(socket);
            } catch (IOException e) {
                socket.close();
                throw e;
            }
        }

        void sendLine(String line) throws IOException {
            if (line.indexOf('\r') >= 0 || line.indexOf('\n') >= 0) {
                throw new IOException("SMTP command contained a line break");
            }
            writer.write(line);
            writer.write("\r\n");
            writer.flush();
        }

        /** Reads a (possibly multi-line) reply and returns its status code. */
        int readReply() throws IOException {
            String line;
            do {
                line = reader.readLine();
                if (line == null) {
                    throw new IOException("SMTP server closed the connection");
                }
            } while (line.length() > 3 && line.charAt(3) == '-');
            if (line.length() < 3) {
                throw new IOException("SMTP server sent a malformed reply");
            }
            try {
                return Integer.parseInt(line.substring(0, 3));
            } catch (NumberFormatException e) {
                throw new IOException("SMTP server sent a malformed status code");
            }
        }

        void expect(int expected) throws IOException {
            expectIn(expected);
        }

        void expectIn(int... expected) throws IOException {
            int actual = readReply();
            for (int code : expected) {
                if (actual == code) {
                    return;
                }
            }
            throw new IOException("SMTP server answered status " + actual);
        }

        void upgradeToTls(String host, int port) throws IOException {
            SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(socket, host, port, true);
            ssl.setUseClientMode(true);
            ssl.startHandshake();
            socket = ssl;
            resetStreams();
        }

        void authenticate(String username, String password) throws IOException {
            Base64.Encoder encoder = Base64.getEncoder();
            sendLine("AUTH LOGIN");
            expect(334);
            sendLine(encoder.encodeToString(username.getBytes(StandardCharsets.UTF_8)));
            expect(334);
            sendLine(encoder.encodeToString(password.getBytes(StandardCharsets.UTF_8)));
            expect(235);
        }

        void writeData(String message) throws IOException {
            String normalized = message.replace("\r\n", "\n").replace('\r', '\n');
            for (String line : normalized.split("\n", -1)) {
                // Dot-stuffing keeps a body line of "." from terminating the message early.
                writer.write(line.startsWith(".") ? "." + line : line);
                writer.write("\r\n");
            }
            writer.write(".\r\n");
            writer.flush();
        }

        private void resetStreams() throws IOException {
            this.reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8);
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // A closed socket at the end of the conversation has nothing left to report.
            }
        }
    }

    /** Rejects an address that could inject an SMTP command or a header line. */
    static void requireSafeAddress(String address, String key) {
        if (address == null || address.isBlank()) {
            throw new ConfigurationException(key + " must not be blank");
        }
        String lower = address.trim().toLowerCase(Locale.ROOT);
        if (lower.indexOf('\r') >= 0 || lower.indexOf('\n') >= 0
                || lower.indexOf('<') >= 0 || lower.indexOf('>') >= 0
                || lower.indexOf(' ') >= 0 || lower.indexOf('@') <= 0) {
            throw new ConfigurationException(key + " is not a valid email address");
        }
    }
}
