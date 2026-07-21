using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// Classifies Linux crash output (glibc abort messages, ASan reports, stack-protector aborts,
/// signals) into named memory-corruption primitives with a difficulty tier and training-audience
/// tag. Built for a lab spanning basic → advanced bugs (PEN-200/301 → GXPN / SANS-760 heap
/// exploitation), so a triaged crash tells you *which* primitive it is (e.g. tcache poisoning vs.
/// a plain null deref), not just "it crashed".
/// </summary>
public static class HeapCorruptionClassifier
{
    public const string TierBasic = "basic";
    public const string TierIntermediate = "intermediate";
    public const string TierAdvanced = "advanced";

    /// <summary>One classified memory-safety finding.</summary>
    public sealed record HeapFinding(
        string Category,
        string Primitive,
        string Cwe,
        string Severity,
        string Tier,
        string Audience,
        string Evidence);

    private sealed record Rule(string Category, Regex Pattern, string Primitive, string Cwe,
        string Severity, string Tier, string Audience);

    private static Regex Sig(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private const string AudBasic = "PEN-200 / PEN-301 (intro memory-safety)";
    private const string AudInter = "PEN-301 / GXPN (exploit dev)";
    private const string AudAdv = "GXPN / SANS-760 (advanced heap exploitation)";

    // Ordered most-specific → most-generic. glibc's own tcache hardening emits these distinctive
    // messages; ASan messages are even more precise. First match wins.
    private static readonly IReadOnlyList<Rule> Rules =
    [
        // —— Advanced glibc heap / tcache primitives ——
        new("tcache-double-free",
            Sig(@"free\(\):\s*double free detected in tcache"),
            "tcache double-free", "CWE-415", "critical", TierAdvanced, AudAdv),
        new("tcache-poisoning",
            Sig(@"malloc\(\):\s*unaligned tcache chunk detected"),
            "tcache poisoning (unaligned tcache chunk)", "CWE-787", "critical", TierAdvanced, AudAdv),
        new("tcache-poisoning",
            Sig(@"malloc\(\):\s*unaligned fastbin chunk detected"),
            "fastbin poisoning (unaligned fastbin chunk)", "CWE-787", "critical", TierAdvanced, AudAdv),
        new("heap-overflow-metadata",
            Sig(@"corrupted size vs\.?\s*prev_size"),
            "heap overflow — corrupted size vs. prev_size", "CWE-122", "critical", TierAdvanced, AudAdv),
        new("unlink-corruption",
            Sig(@"corrupted double-linked list|unsorted double linked list corrupted"),
            "heap metadata corruption (unlink / unsorted-bin)", "CWE-787", "critical", TierAdvanced, AudAdv),
        new("fastbin-dup",
            Sig(@"double free or corruption \((fasttop|out)\)|free\(\):\s*invalid next size \(fast\)"),
            "fastbin dup / invalid next size", "CWE-415", "critical", TierAdvanced, AudAdv),
        new("malloc-corruption",
            Sig(@"malloc\(\):\s*(memory corruption|invalid (size|next size)|corrupted (top|unsorted chunks))"),
            "malloc metadata corruption", "CWE-787", "high", TierAdvanced, AudAdv),
        new("invalid-free",
            Sig(@"free\(\):\s*invalid pointer|munmap_chunk\(\):\s*invalid pointer"),
            "invalid free (wild/mis-aligned pointer)", "CWE-590", "high", TierIntermediate, AudInter),
        new("double-free-generic",
            Sig(@"double free or corruption"),
            "double free / heap corruption", "CWE-415", "critical", TierAdvanced, AudAdv),

        // —— ASan reports (compile-time instrumentation) ——
        new("asan-use-after-free",
            Sig(@"AddressSanitizer:\s*heap-use-after-free"),
            "use-after-free (ASan)", "CWE-416", "critical", TierIntermediate, AudInter),
        new("asan-double-free",
            Sig(@"AddressSanitizer:\s*attempting double-free|AddressSanitizer:.*double-free"),
            "double-free (ASan)", "CWE-415", "critical", TierAdvanced, AudAdv),
        new("asan-heap-overflow",
            Sig(@"AddressSanitizer:\s*heap-buffer-overflow"),
            "heap buffer overflow (ASan)", "CWE-122", "high", TierIntermediate, AudInter),
        new("asan-stack-overflow",
            Sig(@"AddressSanitizer:\s*stack-buffer-overflow"),
            "stack buffer overflow (ASan)", "CWE-121", "high", TierIntermediate, AudInter),
        new("asan-global-overflow",
            Sig(@"AddressSanitizer:\s*global-buffer-overflow"),
            "global buffer overflow (ASan)", "CWE-787", "high", TierIntermediate, AudInter),
        new("asan-generic",
            Sig(@"AddressSanitizer:\s*(SEGV|access|stack-use-after)"),
            "memory-safety violation (ASan)", "CWE-119", "high", TierIntermediate, AudInter),

        // —— Basic stack / generic ——
        new("stack-canary",
            Sig(@"stack smashing detected|__stack_chk_fail"),
            "stack canary tripped (stack buffer overflow)", "CWE-121", "high", TierBasic, AudBasic),
        new("abort-generic",
            Sig(@"SIGABRT|abort\(\)|Aborted"),
            "abort — likely heap/assert guard tripped", "CWE-617", "medium", TierIntermediate, AudInter),
        new("segv-generic",
            Sig(@"SIGSEGV|Segmentation fault|signal 11"),
            "invalid memory access (SIGSEGV)", "CWE-125", "medium", TierBasic, AudBasic),
    ];

    /// <summary>Returns the most-specific finding in <paramref name="text"/>, or null when none match.</summary>
    public static HeapFinding? Classify(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        foreach (var rule in Rules)
        {
            var m = rule.Pattern.Match(text);
            if (m.Success)
            {
                var evidence = ExtractLine(text, m.Index);
                return new HeapFinding(rule.Category, rule.Primitive, rule.Cwe,
                    rule.Severity, rule.Tier, rule.Audience, evidence);
            }
        }

        return null;
    }

    /// <summary>Whether a finding is a heap (as opposed to stack/generic) primitive — for triage tags.</summary>
    public static bool IsHeapPrimitive(HeapFinding finding) =>
        finding.Category.StartsWith("tcache", StringComparison.Ordinal) ||
        finding.Category.Contains("heap", StringComparison.Ordinal) ||
        finding.Category is "unlink-corruption" or "fastbin-dup" or "malloc-corruption"
            or "invalid-free" or "double-free-generic" or "asan-use-after-free" or "asan-double-free";

    private static string ExtractLine(string text, int index)
    {
        var start = text.LastIndexOf('\n', Math.Min(index, text.Length - 1));
        start = start < 0 ? 0 : start + 1;
        var end = text.IndexOf('\n', index);
        if (end < 0) end = text.Length;
        return text[start..end].Trim();
    }
}
