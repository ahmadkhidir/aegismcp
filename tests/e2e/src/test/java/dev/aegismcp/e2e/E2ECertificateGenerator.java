package dev.aegismcp.e2e;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Pure Java hermetic X.509 v3 certificate builder for E2E tests.
 * Generates valid X.509 certificates with SPIFFE SAN extensions.
 * Anchors: FEAT-009, NFR-020.
 */
public class E2ECertificateGenerator {

    private static final byte[] SHA256_RSA_OID = new byte[]{
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b
    };
    private static final byte[] DER_NULL = new byte[]{0x05, 0x00};
    private static final byte[] SAN_OID = new byte[]{0x06, 0x03, 0x55, 0x1d, 0x11};
    private static final byte[] BASIC_CONSTRAINTS_OID = new byte[]{0x06, 0x03, 0x55, 0x1d, 0x13};
    private static final byte[] DER_TRUE = new byte[]{0x01, 0x01, (byte) 0xff};
    private static final byte[] CN_OID = new byte[]{0x06, 0x03, 0x55, 0x04, 0x03};

    public static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static X509Certificate createSelfSignedCa(KeyPair caKeyPair, String caName, Date notBefore, Date notAfter)
            throws Exception {
        return createServerCertificate(caKeyPair, caName, notBefore, notAfter);
    }

    public static X509Certificate createServerCertificate(KeyPair caKeyPair, String serverName, Date notBefore, Date notAfter)
            throws Exception {
        byte[] sigAlg = sequence(SHA256_RSA_OID, DER_NULL);
        byte[] version = tagged(0xa0, derInteger(BigInteger.valueOf(2)));
        byte[] serialNumber = derInteger(BigInteger.valueOf(Math.abs(new Random().nextLong()) + 1));
        byte[] issuer = encodeName(serverName);
        byte[] validity = encodeValidity(notBefore, notAfter);
        byte[] subject = encodeName(serverName);
        byte[] spki = caKeyPair.getPublic().getEncoded();

        List<byte[]> extensionsList = new ArrayList<>();

        // Basic Constraints CA: true
        byte[] cASeq = sequence(DER_TRUE);
        byte[] extValueBc = derOctetString(cASeq);
        byte[] bcExtension = sequence(BASIC_CONSTRAINTS_OID, DER_TRUE, extValueBc);
        extensionsList.add(bcExtension);

        // Subject Alternative Names: [2] DNS: localhost, [7] IP: 127.0.0.1
        List<byte[]> generalNames = new ArrayList<>();
        generalNames.add(tagged(0x82, "localhost".getBytes(StandardCharsets.US_ASCII)));
        generalNames.add(tagged(0x87, new byte[]{(byte) 127, 0, 0, 1}));
        byte[] sanSeq = sequence(generalNames.toArray(new byte[0][]));
        byte[] extValueSan = derOctetString(sanSeq);
        byte[] sanExtension = sequence(SAN_OID, extValueSan);
        extensionsList.add(sanExtension);

        byte[] extensionsSeq = sequence(extensionsList.toArray(new byte[0][]));
        byte[] extensionsTagged = tagged(0xa3, extensionsSeq);

        byte[] tbsCert = sequence(version, serialNumber, sigAlg, issuer, validity, subject, spki, extensionsTagged);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(caKeyPair.getPrivate());
        signer.update(tbsCert);
        byte[] signature = signer.sign();

        byte[] certDer = sequence(tbsCert, sigAlg, derBitString(signature));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    public static X509Certificate createSpiffeSvid(
            PublicKey subjectPublicKey,
            String subjectName,
            PrivateKey issuerPrivateKey,
            String issuerName,
            String spiffeUri,
            Date notBefore,
            Date notAfter
    ) throws Exception {
        List<String> uris = spiffeUri != null ? List.of(spiffeUri) : Collections.emptyList();
        return createCertificate(subjectPublicKey, subjectName, issuerPrivateKey, issuerName, uris, false, notBefore, notAfter);
    }

    public static X509Certificate createCertificate(
            PublicKey subjectPublicKey,
            String subjectName,
            PrivateKey issuerPrivateKey,
            String issuerName,
            List<String> spiffeUris,
            boolean isCa,
            Date notBefore,
            Date notAfter
    ) throws Exception {
        byte[] sigAlg = sequence(SHA256_RSA_OID, DER_NULL);

        byte[] version = tagged(0xa0, derInteger(BigInteger.valueOf(2)));
        byte[] serialNumber = derInteger(BigInteger.valueOf(Math.abs(new Random().nextLong()) + 1));
        byte[] issuer = encodeName(issuerName);
        byte[] validity = encodeValidity(notBefore, notAfter);
        byte[] subject = encodeName(subjectName);
        byte[] spki = subjectPublicKey.getEncoded();

        List<byte[]> extensionsList = new ArrayList<>();

        if (isCa) {
            byte[] cASeq = sequence(DER_TRUE);
            byte[] extValue = derOctetString(cASeq);
            byte[] bcExtension = sequence(BASIC_CONSTRAINTS_OID, DER_TRUE, extValue);
            extensionsList.add(bcExtension);
        }

        if (spiffeUris != null && !spiffeUris.isEmpty()) {
            List<byte[]> generalNames = new ArrayList<>();
            for (String uri : spiffeUris) {
                byte[] uriBytes = uri.getBytes(StandardCharsets.US_ASCII);
                generalNames.add(tagged(0x86, uriBytes));
            }
            byte[] sanSeq = sequence(generalNames.toArray(new byte[0][]));
            byte[] extValue = derOctetString(sanSeq);
            byte[] sanExtension = sequence(SAN_OID, extValue);
            extensionsList.add(sanExtension);
        }

        byte[] extensionsTagged = null;
        if (!extensionsList.isEmpty()) {
            byte[] extensionsSeq = sequence(extensionsList.toArray(new byte[0][]));
            extensionsTagged = tagged(0xa3, extensionsSeq);
        }

        byte[] tbsCert = extensionsTagged != null
                ? sequence(version, serialNumber, sigAlg, issuer, validity, subject, spki, extensionsTagged)
                : sequence(version, serialNumber, sigAlg, issuer, validity, subject, spki);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(issuerPrivateKey);
        signer.update(tbsCert);
        byte[] signature = signer.sign();

        byte[] certDer = sequence(tbsCert, sigAlg, derBitString(signature));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static byte[] encodeName(String cn) throws IOException {
        byte[] cnBytes = cn.getBytes(StandardCharsets.UTF_8);
        byte[] cnValue = tagged(0x0c, cnBytes);
        byte[] atv = sequence(CN_OID, cnValue);
        byte[] rdn = tagged(0x31, atv);
        return sequence(rdn);
    }

    private static byte[] encodeValidity(Date notBefore, Date notAfter) throws IOException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        byte[] nb = tagged(0x17, sdf.format(notBefore).getBytes(StandardCharsets.US_ASCII));
        byte[] na = tagged(0x17, sdf.format(notAfter).getBytes(StandardCharsets.US_ASCII));
        return sequence(nb, na);
    }

    private static byte[] sequence(byte[]... items) throws IOException {
        return tagged(0x30, concat(items));
    }

    private static byte[] derInteger(BigInteger val) throws IOException {
        return tagged(0x02, val.toByteArray());
    }

    private static byte[] derOctetString(byte[] data) throws IOException {
        return tagged(0x04, data);
    }

    private static byte[] derBitString(byte[] data) throws IOException {
        byte[] content = new byte[data.length + 1];
        content[0] = 0x00;
        System.arraycopy(data, 0, content, 1, data.length);
        return tagged(0x03, content);
    }

    private static byte[] tagged(int tag, byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeDerLength(out, data.length);
        out.write(data);
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        } else {
            out.write(0x83);
            out.write((length >> 16) & 0xff);
            out.write((length >> 8) & 0xff);
            out.write(length & 0xff);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) if (a != null) total += a.length;
        byte[] res = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, res, pos, a.length);
                pos += a.length;
            }
        }
        return res;
    }
}
