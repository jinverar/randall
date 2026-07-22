namespace Randall.Infrastructure.BugHunt;

/// <summary>
/// How Bug Hunter exercises a mistake class. Oracle = judgment; Seed = inputs;
/// Static = scan/attribution only (not a fuzz oracle).
/// </summary>
public enum HuntChannel
{
    /// <summary>Oracle engine judges wrong-but-alive behavior.</summary>
    Oracle = 1,
    /// <summary>Seeds / dictionary / mutators provoke the bug (often memory or inject).</summary>
    Seed = 2,
    /// <summary>Static Bug Hunter scan / attribution — not runtime fuzz judgment.</summary>
    Static = 3,
    /// <summary>Both oracle rules and seed/dict provocation.</summary>
    Hybrid = 4,
}

/// <summary>
/// Catalog of AI-codegen / AI-induced weakness classes for the Bug Hunter engine.
/// Informed by classic OWASP-in-codegen patterns and AISW-style AI-induced weaknesses.
/// There is no official "Top 20 AI coding mistakes"; this is Randfuzz's working list
/// with an explicit <see cref="HuntChannel"/> so oracles are not used for seed problems.
/// </summary>
public static class BugHunterMistakes
{
    public sealed record MistakeClass(
        string Id,
        string Title,
        string Description,
        HuntChannel Channel,
        string HuntWith,
        IReadOnlyList<string> OracleHints,
        IReadOnlyList<string> SeedHints,
        IReadOnlyList<string> Refs);

    public static readonly IReadOnlyList<MistakeClass> All =
    [
        // --- Classic OWASP-in-codegen (AI over-produces these) ---
        new(
            "auth-skip",
            "Missing authz / authn checks",
            "AI implements the happy path and forgets gate checks on later handlers (OWASP A01).",
            HuntChannel.Oracle,
            "oracles.auth + oracles.state",
            ["forbidUntil", "requireAuth", "commandRequiresPrior"],
            ["privileged op without prior auth", "GET /admin without cookie"],
            ["OWASP:A01", "AISW-001", "CWE-284", "CWE-306"]),
        new(
            "state-order",
            "State-machine / ordering bugs",
            "Handlers accept REQUEST before BIND, or reuse sessions after logout.",
            HuntChannel.Oracle,
            "oracles.state",
            ["commandRequiresPrior", "forbidResponseInState"],
            ["out-of-order PDUs", "replay after close"],
            ["AISW-001", "CWE-372"]),
        new(
            "inject-sqli",
            "SQL / query injection",
            "String-concat queries from attacker-controlled fields (OWASP A03) — common in AI scaffolds.",
            HuntChannel.Seed,
            "dictionary + web seeds (not a protocol oracle by itself)",
            Array.Empty<string>(),
            ["' OR 1=1--", "1; DROP TABLE", "\" OR \"\"=\""],
            ["OWASP:A03", "CWE-89"]),
        new(
            "inject-cmd",
            "OS command injection",
            "Shell/exec built from user input (OWASP A03).",
            HuntChannel.Seed,
            "dictionary tokens + process crash/oracle if RCE observed",
            Array.Empty<string>(),
            [";id", "| whoami", "$(id)", "`id`"],
            ["OWASP:A03", "CWE-78"]),
        new(
            "inject-xss",
            "Reflected / stored XSS fragments",
            "Unescaped reflection of query/body into HTML (OWASP A03).",
            HuntChannel.Hybrid,
            "web seeds + oracle forbidSubstring on reflected markers when accepted",
            ["forbidSubstring"],
            ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
            ["OWASP:A03", "CWE-79"]),
        new(
            "path-inject",
            "Path traversal / LFI",
            "String-concat paths from attacker-controlled names (OWASP A01/A03).",
            HuntChannel.Hybrid,
            "dictionary + structure/forbid oracles on accepted traversal",
            ["forbidSubstring"],
            ["../", "..\\", "%2e%2e%2f", "/etc/passwd"],
            ["OWASP:A01", "CWE-22"]),
        new(
            "ssrf",
            "Server-side request forgery",
            "AI-written fetch/proxy helpers trust client URLs (common codegen pattern).",
            HuntChannel.Seed,
            "web seeds with internal URLs",
            Array.Empty<string>(),
            ["http://127.0.0.1", "http://169.254.169.254/", "file:///etc/passwd"],
            ["OWASP:A10", "CWE-918"]),
        new(
            "secrets-hardcoded",
            "Hardcoded secrets / credentials",
            "API keys, JWTs, passwords embedded in AI output (OWASP A02 / AISW-005).",
            HuntChannel.Static,
            "Bug Hunter static scan / attribution review (not fuzz)",
            Array.Empty<string>(),
            Array.Empty<string>(),
            ["OWASP:A02", "AISW-005", "CWE-798"]),
        new(
            "crypto-weak",
            "Insecure cryptography",
            "MD5/SHA1 for passwords, ECB, hardcoded IVs (OWASP A02).",
            HuntChannel.Static,
            "static review + targeted crypto tests",
            Array.Empty<string>(),
            Array.Empty<string>(),
            ["OWASP:A02", "CWE-327"]),
        new(
            "error-swallow",
            "Swallowed errors / wrong status",
            "Returns success on failure, or generic OK/200 when validation failed.",
            HuntChannel.Oracle,
            "oracles.invariant expect/forbid + promoteExpectResponse + HTTP status class",
            ["expectSubstring", "forbidSubstring"],
            ["malformed but HTTP/1.1 200", "RPC_OK on bad PDU"],
            ["OWASP:A05", "CWE-390"]),
        new(
            "misconfig",
            "Security misconfiguration",
            "Wildcard CORS, verbose errors, debug left on (OWASP A05) — often AI defaults.",
            HuntChannel.Hybrid,
            "oracle forbidSubstring on stack traces; seeds that trigger verbose errors",
            ["forbidSubstring"],
            ["trigger 500 with stack", "OPTIONS *"],
            ["OWASP:A05"]),

        // --- Protocol / semantic (Randfuzz strength) ---
        new(
            "length-lie",
            "Semantic length / integer mistakes",
            "Length prefixes that do not match bodies; Content-Length lies; trust of client lengths.",
            HuntChannel.Hybrid,
            "oracles.integer + syncContentLength + interesting/boundary mutators",
            ["lengthPrefix", "claimedExceedsPayload"],
            ["hex length fields", "max-int lengths", "short bodies"],
            ["AISW-014", "CWE-130"]),
        new(
            "trust-input",
            "Incorrect structure assumptions",
            "Assumes magic/headers/min sizes always present; accepts truncated frames.",
            HuntChannel.Oracle,
            "oracles.structure",
            ["minSize", "requireMagicHex", "requirePrefix"],
            ["truncated headers", "wrong magic", "empty frames"],
            ["AISW-014", "CWE-20"]),
        new(
            "resource",
            "Resource exhaustion / unbounded work",
            "No caps on response size, fan-out, or decompression-like expansion (AISW-018 / LLM10-shaped).",
            HuntChannel.Oracle,
            "oracles.resource",
            ["maxResponseBytes", "maxPayloadBytes", "responseToPayloadRatio"],
            ["expand mutator", "huge repeats"],
            ["AISW-018", "OWASP-LLM:LLM10"]),

        // --- AI-induced (AISW-style) ---
        new(
            "dep-hallucination",
            "Hallucinated / typosquat dependencies",
            "AI invents package names that attackers register (AISW-003).",
            HuntChannel.Static,
            "static manifest scan — not a fuzz oracle",
            Array.Empty<string>(),
            Array.Empty<string>(),
            ["AISW-003"]),
        new(
            "copy-paste-logic",
            "Copy-paste / divergent branch logic",
            "Duplicated handlers with one path missing a check the other has (AISW-style synthesis drift).",
            HuntChannel.Hybrid,
            "metamorphic + differential vs reference",
            ["whitespaceInsensitive", "duplicateIdempotent", "fileExit"],
            ["near-duplicate valid PDUs"],
            ["AISW-001", "AISW-012"]),
        new(
            "async-racy",
            "Naive concurrency",
            "Shared mutable state without sync in naive async handlers (AISW-017).",
            HuntChannel.Hybrid,
            "runtime timeout + parallel session flows / ThreadSanitizer",
            ["runtime.timeout"],
            ["parallel session flows via campaign"],
            ["AISW-017", "CWE-362"]),
        new(
            "todo-stub",
            "TODO / stub left in hot path",
            "Placeholder handlers that always succeed or always fail.",
            HuntChannel.Static,
            "Bug Hunter attribution on AI blocks + code review",
            Array.Empty<string>(),
            Array.Empty<string>(),
            ["AISW-012"]),
        new(
            "output-bridge",
            "Unsafe output-to-tool / downstream bridging",
            "Unvalidated model or parser output passed to shell/SQL/HTML (OWASP LLM05 shape in codegen).",
            HuntChannel.Hybrid,
            "seeds that poison outputs + oracles on dangerous reflections",
            ["forbidSubstring"],
            ["injection payloads in fields that get re-emitted"],
            ["AISW-008", "OWASP-LLM:LLM05"]),
        new(
            "mem-classic",
            "Classic memory mistakes in mixed/native code",
            "Off-by-one buffers, unchecked copies — often in AI-written C/C++ helpers.",
            HuntChannel.Seed,
            "seeds + mutators + ASan (not primary oracle)",
            Array.Empty<string>(),
            ["cyclic", "expand", "boundary", "interesting"],
            ["CWE-119", "CWE-787"]),
    ];

    public static IEnumerable<MistakeClass> ForChannel(HuntChannel channel) =>
        All.Where(m => m.Channel == channel || m.Channel == HuntChannel.Hybrid);

    public static IEnumerable<MistakeClass> OracleArmed =>
        All.Where(m => m.Channel is HuntChannel.Oracle or HuntChannel.Hybrid);

    public static IEnumerable<MistakeClass> SeedArmed =>
        All.Where(m => m.Channel is HuntChannel.Seed or HuntChannel.Hybrid);

    public static IReadOnlyList<string> DefaultDictionaryTokens() =>
    [
        "../", "..\\", "%2e%2e%2f", "%2e%2e\\",
        "admin", "root", "Authorization: Bearer ", "role=admin", "isAdmin=true",
        "hex:FFFFFFFF", "hex:00000000", "hex:7FFFFFFF", "hex:80000000",
        "null", "undefined", "{}", "[]",
        "%s%s%s%s", "%n",
        "AAAAAAAAAAAAAAAA", "\0", "\r\n\r\n",
        "' OR 1=1--", "1; DROP TABLE--",
        "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
        ";id", "| whoami", "$(id)", "`id`",
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd", "/etc/passwd",
    ];
}
