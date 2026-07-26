namespace Randall.Contracts;

/// <summary>
/// Automatic patch hypothesis — proposes <em>remediation text</em> for teaching /
/// investigation study. Never generates exploit patches, payloads, ROP, or shellcode.
/// Persisted as <c>{guid}_patch_hypothesis.json</c>.
/// </summary>
public sealed record PatchHypothesisDto(
    bool Ok,
    Guid CrashId,
    string Project,
    /// <summary>Educational fix-guidance prose (study text, not a patch file).</summary>
    string RemediationText,
    /// <summary>
    /// When true, a lab differential / patched-binary experiment is suggested
    /// (hook description only — no auto-exploit or auto-patch application).
    /// </summary>
    bool VerifyAgainstPatchedLab,
    /// <summary>How to point a lab tier / differential oracle at a patched binary (experiment hook).</summary>
    string VerifyAgainstPatchedLabHook,
    IReadOnlyList<string> RelatedFunctions,
    IReadOnlyList<string> EvidenceRefs,
    /// <summary>HIGH / MEDIUM / LOW / UNKNOWN</summary>
    string Confidence,
    DateTimeOffset At,
    RootCauseCategory? Category = null,
    string? Error = null);

/// <summary>
/// Patch-analysis workflow summary — security-relevant changed-function and fuzz-target
/// hints from a Ghidra analysis diff. Research/teaching only.
/// Optional persist as <c>patch_analysis_{stamp}.json</c> or caller-chosen path.
/// </summary>
public sealed record PatchAnalysisSummaryDto(
    bool Ok,
    string? CurrentPath,
    string? BaselinePath,
    string Summary,
    IReadOnlyList<string> SecurityRelevantFunctionHints,
    IReadOnlyList<string> FuzzTargetHints,
    IReadOnlyList<RandallAnalysisChangedFunctionDto> TopChanged,
    DateTimeOffset At,
    string? Error = null);
