package dev.aegismcp.cli;

/**
 * Credential-shaped test values. The AWS key is Amazon's published documentation example, not a
 * live credential; it is assembled at runtime so a repository secret scanner sees no credential in
 * the source while the DLP scanner still sees the real pattern.
 */
final class TestCredential {

    static String awsAccessKey() {
        return "AKIA" + "IOSFODNN" + "7EXAMPLE";
    }

    private TestCredential() {
    }
}
