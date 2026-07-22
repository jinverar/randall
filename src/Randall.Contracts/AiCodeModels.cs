namespace Randall.Contracts;

/// <summary>Provenance label for a source region — heuristic, not ground truth.</summary>
public enum AiCodeProvenance
{
    Unknown = 0,
    LikelyHuman = 1,
    LikelyAi = 2,
    AnnotatedAi = 3,
    AnnotatedHuman = 4,
}

/// <summary>One attributed code block (function / marked region / file slice).</summary>
public sealed record AiCodeBlockDto(
    string Path,
    int StartLine,
    int EndLine,
    string Language,
    AiCodeProvenance Provenance,
    double Confidence,
    IReadOnlyList<string> Signals,
    string Preview);

/// <summary>Scan summary for a source tree.</summary>
public sealed record AiCodeScanDto(
    string Root,
    int FilesScanned,
    int AiBlocks,
    int HumanBlocks,
    int UnknownBlocks,
    IReadOnlyList<AiCodeBlockDto> Blocks,
    IReadOnlyList<string> SuggestedOracleFocus,
    IReadOnlyList<string> SuggestedMistakeClasses,
    DateTimeOffset At);

/// <summary>Optional project hook: source roots to attribute before/with fuzzing.</summary>
public sealed class AiCodeConfig
{
    public bool Enabled { get; set; }
    /// <summary>Source directories relative to the project YAML (or absolute).</summary>
    public List<string> SourceRoots { get; set; } = [];
    /// <summary>Glob-ish extensions to include (e.g. .cs, .c, .py, .ts, .go, .rs).</summary>
    public List<string> Extensions { get; set; } =
        [".cs", ".c", ".h", ".cpp", ".cc", ".hpp", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".kt"];
    /// <summary>Write attribution report under corpus/_ai_code/.</summary>
    public bool PersistReport { get; set; } = true;
    /// <summary>On fuzz start, scan sourceRoots and print AI-block hunt targets.</summary>
    public bool ScanOnFuzzStart { get; set; } = true;
    /// <summary>When oracles are missing/empty, merge the AI-mistake oracle pack.</summary>
    public bool AutoArmOracles { get; set; } = true;
    /// <summary>Ensure dictionary mutator + ai_codegen_mistakes.txt tokens are active.</summary>
    public bool AutoArmDictionary { get; set; } = true;
}

/// <summary>Plan produced by <c>randall ai hunt</c> — what to fuzz for AI bad-code bugs.</summary>
public sealed record AiCodeHuntPlanDto(
    AiCodeScanDto Scan,
    IReadOnlyList<AiCodeBlockDto> PriorityAiBlocks,
    IReadOnlyList<string> MistakeClasses,
    IReadOnlyList<string> OracleFocus,
    string DictionaryHint,
    string Summary);
