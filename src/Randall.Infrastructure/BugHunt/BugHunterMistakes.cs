namespace Randall.Infrastructure.BugHunt;

/// <summary>
/// Catalog of common LLM / AI-codegen mistake classes and how Randfuzz hunts them.
/// Oracles own semantic failures; seeds/mutators own memory bugs.
/// </summary>
public static class BugHunterMistakes
{
    public sealed record MistakeClass(
        string Id,
        string Title,
        string Description,
        string HuntWith,
        IReadOnlyList<string> OracleHints,
        IReadOnlyList<string> SeedHints);

    public static readonly IReadOnlyList<MistakeClass> All =
    [
        new(
            "auth-skip",
            "Missing authz / authn checks",
            "AI often implements the happy path and forgets gate checks on later handlers.",
            "oracles.auth + oracles.state",
            ["forbidUntil", "requireAuth", "commandRequiresPrior"],
            ["valid session then privileged op without prior auth"]),
        new(
            "state-order",
            "State-machine / ordering bugs",
            "Handlers accept REQUEST before BIND, or reuse sessions after logout.",
            "oracles.state",
            ["commandRequiresPrior", "forbidResponseInState"],
            ["out-of-order PDUs", "replay after close"]),
        new(
            "length-lie",
            "Semantic length / integer mistakes",
            "Length prefixes that do not match bodies, off-by-one sizes, trust of client lengths.",
            "oracles.integer + interesting/boundary mutators",
            ["lengthPrefix", "claimedExceedsPayload"],
            ["hex length fields", "max-int lengths", "short bodies"]),
        new(
            "trust-input",
            "Incorrect structure assumptions",
            "Assumes magic/headers/min sizes always present; accepts truncated frames.",
            "oracles.structure",
            ["minSize", "requireMagicHex", "requirePrefix"],
            ["truncated headers", "wrong magic", "empty frames"]),
        new(
            "resource",
            "Resource exhaustion / unbounded work",
            "No caps on response size, fan-out, or decompression-like expansion.",
            "oracles.resource",
            ["maxResponseBytes", "maxPayloadBytes", "responseToPayloadRatio"],
            ["expand mutator", "huge repeats"]),
        new(
            "error-swallow",
            "Swallowed errors / wrong status",
            "Returns success on failure, or generic OK when validation failed.",
            "oracles.invariant expect/forbid + promoteExpectResponse",
            ["expectSubstring", "forbidSubstring"],
            ["malformed but OK responses"]),
        new(
            "path-inject",
            "Path / command construction",
            "String-concat paths or shell fragments from attacker-controlled names.",
            "dictionary tokens + structure oracles",
            ["forbidSubstring for path traversal markers in accepted responses"],
            ["../", "..\\", "%2e%2e"]),
        new(
            "copy-paste-logic",
            "Copy-paste logic bugs",
            "Duplicated branches with one path missing a check the other has.",
            "metamorphic + differential vs reference",
            ["whitespaceInsensitive", "duplicateIdempotent", "fileExit"],
            ["near-duplicate valid PDUs"]),
        new(
            "async-racy",
            "Naive concurrency",
            "Shared mutable state without sync in naive async handlers.",
            "runtime timeout/deadlock + ThreadSanitizer builds",
            ["runtime.timeout"],
            ["parallel session flows via campaign"]),
        new(
            "mem-classic",
            "Classic memory mistakes still present in mixed code",
            "Off-by-one buffers, unchecked copies — often in AI-written C/C++ helpers.",
            "seeds + mutators + ASan (not primary oracle)",
            Array.Empty<string>(),
            ["cyclic", "expand", "boundary", "interesting"]),
    ];

    public static IReadOnlyList<string> DefaultDictionaryTokens() =>
    [
        "../",
        "..\\",
        "%2e%2e%2f",
        "admin",
        "Authorization: Bearer ",
        "role=admin",
        "hex:FFFFFFFF",
        "hex:00000000",
        "hex:7FFFFFFF",
        "hex:80000000",
        "null",
        "undefined",
        "{}",
        "[]",
        "%s%s%s%s",
        "%n",
        "AAAAAAAAAAAAAAAA",
        "\0",
        "\r\n\r\n",
    ];
}
