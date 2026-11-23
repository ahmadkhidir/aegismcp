package dev.aegismcp.gateway.dlp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Single-pass candidate scanner for outbound tool responses.
 *
 * <p>Scanning a 1 MB payload with every pattern applied to the whole payload costs hundreds of
 * milliseconds: Java regular expressions are quadratic in word-boundary lookarounds and the entropy
 * candidate expression alone sweeps every byte. This scanner walks the payload once, tracks token
 * runs and the digits inside them, and only hands a bounded neighbourhood to the relevant compiled
 * pattern. Work is therefore proportional to the number of candidates rather than to the payload
 * size, which is what NFR-002 requires.
 *
 * <p>Payloads that begin with a JSON object or array are scanned inside string literals only, so a
 * numeric value is never rewritten and the document keeps its structure. String keys are exempt:
 * a redacted key would silently rename a field of the upstream result.
 *
 * <p>Detections carry offsets in the units of the scanned payload: byte offsets for a UTF-8 byte
 * payload and character offsets for a character payload. Because every pattern is ASCII, a UTF-8
 * continuation byte can never be part of a match, so byte offsets stay exact.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
public final class DlpScanner {

    private static final int TOKEN = 1;
    private static final int DIGIT = 2;

    /** Marks a trigger that fires anywhere, not only at the first character of a token run. */
    private static final int ANY_POSITION = 0x40;

    private static final byte SP_AT = 1 | ANY_POSITION;
    private static final byte SP_COLON = 2 | ANY_POSITION;
    private static final byte SP_AWS = 3;
    private static final byte SP_SECRET = 4;
    private static final byte SP_SECRET_LABEL = 5;
    private static final byte SP_GITHUB = 6;
    private static final byte SP_BEARER = 7;
    private static final byte SP_JDBC = 8;
    private static final byte SP_PEM = 9;

    /** Character classes for the payload walk. Only ASCII participates in a pattern. */
    private static final byte[] CLASS = new byte[256];

    /** Single-byte triggers that can start a candidate. */
    private static final byte[] SPECIAL = new byte[256];

    static {
        for (int c = '0'; c <= '9'; c++) {
            CLASS[c] = TOKEN | DIGIT;
        }
        for (int c = 'a'; c <= 'z'; c++) {
            CLASS[c] = TOKEN;
        }
        for (int c = 'A'; c <= 'Z'; c++) {
            CLASS[c] = TOKEN;
        }
        for (char c : new char[]{'+', '/', '=', '_', '-'}) {
            CLASS[c] = TOKEN;
        }

        SPECIAL['@'] = SP_AT;
        SPECIAL[':'] = SP_COLON;
        SPECIAL['A'] = SP_AWS;
        SPECIAL['s'] = SP_SECRET;
        SPECIAL['S'] = SP_SECRET;
        SPECIAL['_'] = SP_SECRET_LABEL;
        SPECIAL['g'] = SP_GITHUB;
        SPECIAL['b'] = SP_BEARER;
        SPECIAL['B'] = SP_BEARER;
        SPECIAL['j'] = SP_JDBC;
        SPECIAL['-'] = SP_PEM;
    }

    private static final String[] AWS_KEY_PREFIXES = {
            "AKIA", "ASIA", "AROA", "AIPA", "ANPA", "ANVA", "AGPA"
    };

    /** How far past its trigger a credential or connection-string match may extend. */
    private static final int CREDENTIAL_WINDOW = 160;
    private static final int CONNECTION_WINDOW = 512;
    /** How far the local part or domain of an address may reach from its {@code @}. */
    private static final int ADDRESS_WINDOW = 96;
    /** Upper bound on the body of a PEM block, so a stray header cannot scan the whole payload. */
    private static final int PEM_SEARCH_LIMIT = 64 * 1024;
    /** Separators that keep grouped digits in one PII candidate ("4111 1111", "(555) 234-5678"). */
    private static final int NUMERIC_CONTEXT_LIMIT = 24;

    private final DlpPatternMatcher patterns;
    private final ShannonEntropyScanner entropy;
    private final boolean entropyEnabled;
    private final int minEntropyTokenLength;

    public DlpScanner(DlpConfig config) {
        Objects.requireNonNull(config, "config must not be null");
        this.patterns = new DlpPatternMatcher(config);
        this.entropy = new ShannonEntropyScanner(config);
        this.entropyEnabled = config.isEnableEntropyScanner();
        this.minEntropyTokenLength = config.getMinEntropyTokenLength();
    }

    /** Scans a character payload as free text, with no JSON structure assumed. */
    public List<DlpDetection> scanText(String text) {
        List<DlpDetection> detections = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return detections;
        }
        char[] chars = text.toCharArray();
        scan(Payload.ofChars(chars), 0, chars.length, false, detections);
        return detections;
    }

    /** Scans a character payload that holds a JSON document, inspecting string values only. */
    public List<DlpDetection> scanJsonText(String json) {
        List<DlpDetection> detections = new ArrayList<>();
        if (json == null || json.isEmpty()) {
            return detections;
        }
        char[] chars = json.toCharArray();
        scan(Payload.ofChars(chars), 0, chars.length, true, detections);
        return detections;
    }

    /** Scans a byte payload as free text, with no JSON structure assumed. */
    public List<DlpDetection> scanBytes(byte[] payload) {
        List<DlpDetection> detections = new ArrayList<>();
        if (payload == null || payload.length == 0) {
            return detections;
        }
        scanBytes(payload, 0, payload.length, false, detections);
        return detections;
    }

    /** Scans a byte payload that holds a JSON document, inspecting string values only. */
    public List<DlpDetection> scanJsonBytes(byte[] payload) {
        List<DlpDetection> detections = new ArrayList<>();
        if (payload == null || payload.length == 0) {
            return detections;
        }
        scanBytes(payload, 0, payload.length, true, detections);
        return detections;
    }

    /**
     * Returns true when the payload starts, after optional whitespace, with a JSON object or array.
     */
    public static boolean looksLikeJson(byte[] payload) {
        if (payload == null) {
            return false;
        }
        for (byte b : payload) {
            if (b == ' ' || b == '\t' || b == '\r' || b == '\n') {
                continue;
            }
            return b == '{' || b == '[';
        }
        return false;
    }

    private void scan(Payload payload, int from, int to, boolean json, List<DlpDetection> out) {
        int runStart = -1;
        int runLen = 0;
        int runDigits = 0;
        boolean inString = !json;
        int stringMark = 0;

        for (int i = from; i < to; i++) {
            int c = payload.at(i);

            if (json) {
                if (!inString) {
                    if (c == '"') {
                        inString = true;
                        stringMark = out.size();
                        runStart = -1;
                        runLen = 0;
                    }
                    continue;
                }
                if (c == '\\') {
                    if (runLen != 0) {
                        endRun(payload, runStart, i, runDigits, out);
                        runStart = -1;
                        runLen = 0;
                    }
                    i++;
                    continue;
                }
                if (c == '"') {
                    if (runLen != 0) {
                        endRun(payload, runStart, i, runDigits, out);
                        runStart = -1;
                        runLen = 0;
                    }
                    inString = false;
                    if (isKey(payload, i + 1, to)) {
                        dropFrom(out, stringMark);
                    }
                    continue;
                }
            }

            int cls = c >= 0 && c < 256 ? CLASS[c] : 0;

            if ((cls & TOKEN) == 0) {
                int closedRunStart = runStart;
                if (runLen != 0) {
                    endRun(payload, runStart, i, runDigits, out);
                    runStart = -1;
                    runLen = 0;
                }
                if (c >= 0 && c < 256) {
                    byte trigger = SPECIAL[c];
                    if ((trigger & ANY_POSITION) != 0) {
                        // The trigger closes the run it follows: ":" after a scheme, "@" after a local part.
                        onTrigger(payload, trigger, i, from, to, closedRunStart, out);
                    }
                }
                continue;
            }

            if (runLen == 0) {
                runStart = i;
                runDigits = 0;
                if (c < 256) {
                    byte trigger = SPECIAL[c];
                    if (trigger != 0) {
                        onTrigger(payload, trigger, i, from, to, runStart, out);
                    }
                }
            }
            runLen++;
            runDigits += cls >> 1;
        }

        if (runLen != 0) {
            endRun(payload, runStart, to, runDigits, out);
        }
    }

    /**
     * Byte-payload walk. Mirrors {@link #scan} statement for statement, but indexes the array directly:
     * this is the production path for a UTF-8 response body, and removing the accessor call there is
     * worth the duplication. Keep the two loops in step.
     */
    private void scanBytes(byte[] data, int from, int to, boolean json, List<DlpDetection> out) {
        Payload payload = Payload.ofBytes(data);
        int runStart = -1;
        int runLen = 0;
        int runDigits = 0;
        boolean inString = !json;
        int stringMark = 0;

        for (int i = from; i < to; i++) {
            int c = data[i] & 0xFF;

            if (json) {
                if (!inString) {
                    if (c == '"') {
                        inString = true;
                        stringMark = out.size();
                        runStart = -1;
                        runLen = 0;
                    }
                    continue;
                }
                if (c == '\\') {
                    if (runLen != 0) {
                        endRun(payload, runStart, i, runDigits, out);
                        runStart = -1;
                        runLen = 0;
                    }
                    i++;
                    continue;
                }
                if (c == '"') {
                    if (runLen != 0) {
                        endRun(payload, runStart, i, runDigits, out);
                        runStart = -1;
                        runLen = 0;
                    }
                    inString = false;
                    if (isKey(payload, i + 1, to)) {
                        dropFrom(out, stringMark);
                    }
                    continue;
                }
            }

            int cls = CLASS[c];

            if ((cls & TOKEN) == 0) {
                int closedRunStart = runStart;
                if (runLen != 0) {
                    endRun(payload, runStart, i, runDigits, out);
                    runStart = -1;
                    runLen = 0;
                }
                byte trigger = SPECIAL[c];
                if ((trigger & ANY_POSITION) != 0) {
                    onTrigger(payload, trigger, i, from, to, closedRunStart, out);
                }
                continue;
            }

            if (runLen == 0) {
                runStart = i;
                runDigits = 0;
                byte trigger = SPECIAL[c];
                if (trigger != 0) {
                    onTrigger(payload, trigger, i, from, to, runStart, out);
                }
            }
            runLen++;
            runDigits += cls >> 1;
        }

        if (runLen != 0) {
            endRun(payload, runStart, to, runDigits, out);
        }
    }

    /**
     * Closes a token run. Both downstream checks are rare, so the common short, digit-free run costs
     * two comparisons and nothing else.
     */
    private void endRun(Payload payload, int start, int end, int digits, List<DlpDetection> out) {
        if (digits >= 3) {
            scanNumericGroup(payload, start, end, out);
        }
        if (entropyEnabled && end - start >= minEntropyTokenLength) {
            entropy.scan(payload.sequence(), start, end, out);
        }
    }

    /**
     * Widens a digit-bearing token run to the numeric group around it ("4111 1111 1111 1111",
     * "(555) 234-5678") and applies the PII patterns when the group is long enough to be one.
     */
    private void scanNumericGroup(Payload payload, int start, int end, List<DlpDetection> out) {
        int groupStart = start;
        int groupEnd = end;
        for (int steps = 0; groupStart > 0 && steps < NUMERIC_CONTEXT_LIMIT
                && isNumericContext(payload.at(groupStart - 1)); steps++) {
            groupStart--;
        }
        for (int steps = 0; groupEnd < payload.length() && steps < NUMERIC_CONTEXT_LIMIT
                && isNumericContext(payload.at(groupEnd)); steps++) {
            groupEnd++;
        }

        if (countDigits(payload, groupStart, groupEnd) < 7) {
            return;
        }

        CharSequence text = payload.sequence();
        patterns.scan(DlpPatternType.PHONE_NUMBER, text, groupStart, groupEnd, out);
        patterns.scan(DlpPatternType.SSN, text, groupStart, groupEnd, out);
        patterns.scan(DlpPatternType.CREDIT_CARD, text, groupStart, groupEnd, out);
    }

    private void onTrigger(Payload payload, byte trigger, int i, int from, int to, int runStart,
                           List<DlpDetection> out) {
        CharSequence text = payload.sequence();
        switch (trigger) {
            case SP_AT -> {
                if (i > from && isToken(payload.at(i - 1)) && i + 1 < to && isToken(payload.at(i + 1))) {
                    int start = Math.max(from, i - ADDRESS_WINDOW);
                    int end = Math.min(to, i + ADDRESS_WINDOW);
                    patterns.scan(DlpPatternType.EMAIL_ADDRESS, text, start, end, out);
                }
            }
            case SP_COLON -> {
                if (i + 2 < to && payload.at(i + 1) == '/' && payload.at(i + 2) == '/') {
                    int schemeStart = runStart >= 0 ? runStart : i;
                    patterns.scan(DlpPatternType.DATABASE_CONNECTION_STRING, text, schemeStart,
                            Math.min(to, schemeStart + CONNECTION_WINDOW), out);
                }
            }
            case SP_AWS -> {
                if (i == runStart && hasAwsPrefix(payload, i, to)) {
                    patterns.scan(DlpPatternType.AWS_ACCESS_KEY, text, i, Math.min(to, i + 20), out);
                }
            }
            case SP_SECRET -> {
                if (i == runStart && i + 2 < to && payload.at(i + 1) == 'k' && payload.at(i + 2) == '-') {
                    patterns.scan(DlpPatternType.OPENAI_API_KEY, text, i,
                            Math.min(to, i + CREDENTIAL_WINDOW), out);
                } else if (i == runStart && regionMatchesIgnoreCase(payload, i, "secret", to)) {
                    patterns.scan(DlpPatternType.AWS_SECRET_KEY, text, i,
                            Math.min(to, i + CREDENTIAL_WINDOW), out);
                }
            }
            case SP_SECRET_LABEL -> {
                // Catches labels such as "aws_secret_access_key", where "secret" does not begin the run.
                if (regionMatchesIgnoreCase(payload, i + 1, "secret", to)) {
                    int start = runStart >= 0 ? runStart : i + 1;
                    patterns.scan(DlpPatternType.AWS_SECRET_KEY, text, start,
                            Math.min(to, start + CREDENTIAL_WINDOW), out);
                }
            }
            case SP_GITHUB -> {
                if (i == runStart && hasGithubPrefix(payload, i, to)) {
                    patterns.scan(DlpPatternType.GITHUB_TOKEN, text, i,
                            Math.min(to, i + CREDENTIAL_WINDOW), out);
                }
            }
            case SP_BEARER -> {
                if (i == runStart && regionMatchesIgnoreCase(payload, i, "bearer", to)
                        && i + 6 < to && isWhitespace(payload.at(i + 6))) {
                    patterns.scan(DlpPatternType.BEARER_TOKEN, text, i,
                            Math.min(to, i + CONNECTION_WINDOW), out);
                }
            }
            case SP_JDBC -> {
                if (i == runStart && regionMatches(payload, i, "jdbc:", to)) {
                    patterns.scan(DlpPatternType.JDBC_CONNECTION_STRING, text, i,
                            Math.min(to, i + CONNECTION_WINDOW), out);
                }
            }
            case SP_PEM -> {
                if (i == runStart && regionMatches(payload, i, "-----BEGIN", to)) {
                    int end = pemBlockEnd(payload, i, to);
                    if (end > i) {
                        patterns.scan(DlpPatternType.PEM_PRIVATE_KEY, text, i, end, out);
                        patterns.scan(DlpPatternType.PGP_PRIVATE_KEY, text, i, end, out);
                    }
                }
            }
            default -> {
                // No other trigger exists.
            }
        }
    }

    /** Returns the end offset of a PEM block header starting at {@code start}, or the bound when unterminated. */
    private int pemBlockEnd(Payload payload, int start, int to) {
        int limit = Math.min(to, start + PEM_SEARCH_LIMIT);
        for (int i = start + 10; i + 8 < limit; i++) {
            if (payload.at(i) == '-' && regionMatches(payload, i, "-----END", limit)) {
                return Math.min(limit, i + 40);
            }
        }
        return limit;
    }

    private boolean hasAwsPrefix(Payload payload, int index, int to) {
        for (String prefix : AWS_KEY_PREFIXES) {
            if (index + prefix.length() < to && regionMatches(payload, index, prefix, to)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasGithubPrefix(Payload payload, int index, int to) {
        if (index + 4 < to && payload.at(index + 1) == 'h') {
            int third = payload.at(index + 2);
            if ((third == 'p' || third == 'o' || third == 'u' || third == 's' || third == 'r')
                    && payload.at(index + 3) == '_') {
                return true;
            }
        }
        return regionMatches(payload, index, "github_pat_", to);
    }

    private static boolean regionMatches(Payload payload, int index, String expected, int to) {
        int length = expected.length();
        if (index < 0 || index + length > to) {
            return false;
        }
        for (int k = 0; k < length; k++) {
            if (payload.at(index + k) != expected.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    private static boolean regionMatchesIgnoreCase(Payload payload, int index, String expected, int to) {
        int length = expected.length();
        if (index < 0 || index + length > to) {
            return false;
        }
        for (int k = 0; k < length; k++) {
            int actual = payload.at(index + k);
            if (actual != expected.charAt(k) && Character.toLowerCase(actual) != expected.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isToken(int c) {
        return c >= 0 && c < 256 && (CLASS[c] & TOKEN) != 0;
    }

    private static boolean isWhitespace(int c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    private static boolean isNumericContext(int c) {
        return (c >= '0' && c <= '9') || c == '-' || c == ' ' || c == '.' || c == '(' || c == ')' || c == '+';
    }

    private static int countDigits(Payload payload, int from, int to) {
        int digits = 0;
        for (int i = from; i < to && digits < 32; i++) {
            int c = payload.at(i);
            if (c >= '0' && c <= '9') {
                digits++;
            }
        }
        return digits;
    }

    /** True when the string that ended at {@code quote} is an object key rather than a value. */
    private static boolean isKey(Payload payload, int from, int to) {
        for (int i = from; i < to; i++) {
            int c = payload.at(i);
            if (c == ':') {
                return true;
            }
            if (!isWhitespace(c)) {
                return false;
            }
        }
        return false;
    }

    private static void dropFrom(List<DlpDetection> out, int mark) {
        while (out.size() > mark) {
            out.remove(out.size() - 1);
        }
    }

    /**
     * Random-access view over the payload being scanned, plus a sequence for regex regions.
     *
     * <p>A single concrete class keeps the per-character access monomorphic so the walk inlines it;
     * two subclasses would double the dispatch cost of the hottest loop in the gateway.
     */
    private static final class Payload {
        private final byte[] bytes;
        private final char[] chars;
        private final CharSequence sequence;

        private Payload(byte[] bytes, char[] chars, CharSequence sequence) {
            this.bytes = bytes;
            this.chars = chars;
            this.sequence = sequence;
        }

        static Payload ofBytes(byte[] bytes) {
            return new Payload(bytes, null, new AsciiByteSequence(bytes));
        }

        static Payload ofChars(char[] chars) {
            return new Payload(null, chars, new CharArraySequence(chars));
        }

        int length() {
            return bytes != null ? bytes.length : chars.length;
        }

        int at(int index) {
            return bytes != null ? bytes[index] & 0xFF : chars[index];
        }

        CharSequence sequence() {
            return sequence;
        }
    }

    /** ASCII view over a UTF-8 byte payload: every byte maps to the code point it encodes. */
    private static final class AsciiByteSequence implements CharSequence {
        private final byte[] bytes;

        AsciiByteSequence(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public int length() {
            return bytes.length;
        }

        @Override
        public char charAt(int index) {
            return (char) (bytes[index] & 0xFF);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new String(bytes, start, end - start, StandardCharsets.ISO_8859_1);
        }

        @Override
        public String toString() {
            return new String(bytes, StandardCharsets.ISO_8859_1);
        }
    }

    private static final class CharArraySequence implements CharSequence {
        private final char[] chars;

        CharArraySequence(char[] chars) {
            this.chars = chars;
        }

        @Override
        public int length() {
            return chars.length;
        }

        @Override
        public char charAt(int index) {
            return chars[index];
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new String(chars, start, end - start);
        }

        @Override
        public String toString() {
            return new String(chars);
        }
    }
}
