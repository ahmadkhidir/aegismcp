package dev.aegismcp.e2e.fixtures;

import dev.aegismcp.e2e.generators.E2ECertificateGenerator;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Hermetic TLS material for one gateway process: a self-signed certificate authority that also
 * serves as the listener certificate, and a client SVID signed by it.
 *
 * <p>The gateway trusts only this authority, and the test client trusts only this authority, so the
 * suite never depends on a public certificate or the workstation trust store (FEAT-009, C-001,
 * C-023).
 */
public final class TlsMaterial {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String SPIFFE_ID = "spiffe://aegis.dev/ns/e2e/sa/agent-worker";

    public final Path serverKeystore;
    public final Path serverTruststore;
    public final Path clientKeystore;
    public final Path clientTruststore;
    public final Path trustBundlePem;
    public final String spiffeId = SPIFFE_ID;

    private TlsMaterial(
            Path serverKeystore,
            Path serverTruststore,
            Path clientKeystore,
            Path clientTruststore,
            Path trustBundlePem
    ) {
        this.serverKeystore = serverKeystore;
        this.serverTruststore = serverTruststore;
        this.clientKeystore = clientKeystore;
        this.clientTruststore = clientTruststore;
        this.trustBundlePem = trustBundlePem;
    }

    public static TlsMaterial generate(Path directory) throws Exception {
        Files.createDirectories(directory);
        KeyPair authority = E2ECertificateGenerator.generateRsaKeyPair();
        Date notBefore = Date.from(Instant.now().minus(Duration.ofMinutes(5)));
        Date notAfter = Date.from(Instant.now().plus(Duration.ofDays(2)));
        X509Certificate authorityCertificate = E2ECertificateGenerator.createSelfSignedCa(
                authority, "aegis-e2e-ca", notBefore, notAfter);

        // The authority certificate carries the listener name in its SAN (localhost and
        // 127.0.0.1), so it also serves as the listener certificate the client validates.
        KeyPair server = authority;
        X509Certificate serverCertificate = authorityCertificate;

        KeyPair client = E2ECertificateGenerator.generateRsaKeyPair();
        X509Certificate clientCertificate = E2ECertificateGenerator.createSpiffeSvid(
                client.getPublic(), "aegis-e2e-agent",
                authority.getPrivate(), "aegis-e2e-ca",
                SPIFFE_ID, notBefore, notAfter);

        Path serverKeystore = directory.resolve("gateway-server.p12");
        writeKeyStore(serverKeystore, "server", server.getPrivate(),
                new Certificate[]{serverCertificate});

        Path serverTruststore = directory.resolve("gateway-trust.p12");
        writeTrustStore(serverTruststore, "authority", authorityCertificate);

        Path clientKeystore = directory.resolve("gateway-client.p12");
        writeKeyStore(clientKeystore, "client", client.getPrivate(),
                new Certificate[]{clientCertificate, authorityCertificate});

        Path clientTruststore = directory.resolve("client-trust.p12");
        writeTrustStore(clientTruststore, "authority", authorityCertificate);

        Path trustBundle = directory.resolve("spiffe-trust.pem");
        Files.writeString(trustBundle, pem(authorityCertificate));

        return new TlsMaterial(serverKeystore, serverTruststore, clientKeystore, clientTruststore, trustBundle);
    }

    public char[] password() {
        return PASSWORD.clone();
    }

    /** A client context that trusts the harness authority and presents no peer certificate. */
    public SSLContext anonymousClientContext() throws Exception {
        return context(null, clientTruststore);
    }

    /** A client context that trusts the harness authority and presents the signed SPIFFE SVID. */
    public SSLContext mtlsClientContext() throws Exception {
        return context(clientKeystore, clientTruststore);
    }

    private static SSLContext context(Path keyStorePath, Path trustStorePath) throws Exception {
        KeyManagerFactory keyManagers = null;
        if (keyStorePath != null) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(keyStorePath)) {
                keyStore.load(input, PASSWORD);
            }
            keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, PASSWORD);
        }

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(trustStorePath)) {
            trustStore.load(input, PASSWORD);
        }
        TrustManagerFactory trustManagers =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers != null ? keyManagers.getKeyManagers() : null,
                trustManagers.getTrustManagers(), null);
        return context;
    }

    private static void writeKeyStore(
            Path path,
            String alias,
            java.security.PrivateKey key,
            Certificate[] chain
    ) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry(alias, key, PASSWORD, chain);
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, PASSWORD);
        }
    }

    private static void writeTrustStore(Path path, String alias, Certificate certificate) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry(alias, certificate);
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, PASSWORD);
        }
    }

    private static String pem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
    }
}
