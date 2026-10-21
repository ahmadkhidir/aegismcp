package dev.aegismcp.gateway.dlp;

/**
 * Fast zero-allocation Luhn algorithm check to eliminate credit card false positives.
 * Anchors: FEAT-005, NFR-002.
 */
public final class LuhnValidator {

    private LuhnValidator() {
    }

    /**
     * Validates whether a numeric string conforms to the Luhn checksum.
     * Ignores spaces and hyphens.
     */
    public static boolean isValidCreditCard(CharSequence input, int start, int end) {
        int sum = 0;
        int digitCount = 0;
        boolean alternate = false;

        // Traverse right-to-left
        for (int i = end - 1; i >= start; i--) {
            char c = input.charAt(i);
            if (c == ' ' || c == '-') {
                continue;
            }
            if (c < '0' || c > '9') {
                return false;
            }

            int n = c - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) {
                    n -= 9;
                }
            }
            sum += n;
            digitCount++;
            alternate = !alternate;
        }

        // Standard major credit cards are between 13 and 19 digits
        if (digitCount < 13 || digitCount > 19) {
            return false;
        }

        return (sum % 10 == 0);
    }
}
