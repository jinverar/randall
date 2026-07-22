namespace Randall.Contracts;

/// <summary>Provenance label for a source region — heuristic, not ground truth.</summary>
public enum BugHunterProvenance
{
    Unknown = 0,
    LikelyHuman = 1,
    LikelyAi = 2,
    AnnotatedAi = 3,
    AnnotatedHuman = 4,
}

/// <summary>One attributed code block (function / marked region / file slice).</summary>
public sealed record BugHunterBlockDto(
    string Path,
    int StartLine,
    int EndLine,
    string Language,
    BugHunterProvenance Provenance,
    double Confidence,
    IReadOnlyList<string> Signals,
    string Preview);

/// <summary>Scan summary for a source tree.</summary>
public sealed record BugHunterScanDto(
    string Root,
    int FilesScanned,
    int AiBlocks,
    int HumanBlocks,
    int UnknownBlocks,
    IReadOnlyList<BugHunterBlockDto> Blocks,
    IReadOnlyList<string> SuggestedOracleFocus,
    IReadOnlyList<string> SuggestedMistakeClasses,
    DateTimeOffset At);

/// <summary>
/// Bug Hunter engine project config — AI/human analysis + hunt arming.
/// Does not evaluate target behavior (that is <see cref="OracleConfig"/>).
/// </summary>
public sealed class BugHunterConfig
{
    public bool Enabled { get; set; }
    /// <summary>Source directories relative to the project YAML (or absolute).</summary>
    public List<string> SourceRoots { get; set; } = [];
    /// <summary>Glob-ish extensions to include (e.g. .cs, .c, .py, .ts, .go, .rs).</summary>
    public List<string> Extensions { get; set; } =
        [".cs", ".c", ".h", ".cpp", ".cc", ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".kt"];
    /// <summary>Write attribution + hunt plan under corpus/_bug_hunter/ (and legacy _ai_code/).</summary>
    public bool PersistReport { get; set; } = true;
    /// <summary>On fuzz start, scan sourceRoots and print AI-block hunt targets.</summary>
    public bool ScanOnFuzzStart { get; set; } = true;
    /// <summary>Suggest/merge oracle rules for AI mistake classes (Oracle engine still judges).</summary>
    public bool AutoArmOracles { get; set; } = true;
    /// <summary>Ensure dictionary mutator + AI-mistake tokens are active.</summary>
    public bool AutoArmDictionary { get; set; } = true;
}

/// <summary>Plan produced by the Bug Hunter engine — what to stress next.</summary>
public sealed record BugHunterPlanDto(
    BugHunterScanDto Scan,
    IReadOnlyList<BugHunterBlockDto> PriorityAiBlocks,
    IReadOnlyList<string> MistakeClasses,
    IReadOnlyList<string> OracleFocus,
    string DictionaryHint,
    string Summary);
