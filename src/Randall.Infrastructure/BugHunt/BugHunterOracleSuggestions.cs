using Randall.Contracts;

namespace Randall.Infrastructure.BugHunt;

/// <summary>
/// Bug Hunter to Oracle bridge: suggested rule pack for common AI-codegen bugs.
/// Merged into oracles: for the Oracle engine to judge; this type does not evaluate runs.
/// Auth and length-prefix are NOT auto-armed (need explicit project enablement / modeled fields).
/// Remaining AI rules are marked Experimental until validated on the target.
/// </summary>
public static class BugHunterOracleSuggestions
{
    public const string DictionaryRelativePath = "dictionaries/ai_codegen_mistakes.txt";

    /// <summary>Build a fresh oracle config tuned for AI mistakes (safe defaults).</summary>
    public static OracleConfig Create() => new()
    {
        Enabled = true,
        AuthEnabled = false,
        RetainOnViolation = true,
        RetainOnNearMiss = true,
        PersistFindings = true,
        PromoteExpectResponse = true,
        PromotePostReceiveAbort = true,
        InvariantSeverity = "violation",
        // Auth / length-prefix omitted: require project authEnabled + modeled length fields.
        Auth = [],
        Integer = [],
        State =
        [
            new OracleStateRuleConfig
            {
                Id = "ai-request-needs-bind",
                Type = "commandRequiresPrior",
                ForCommand = "REQUEST",
                PriorCommand = "BIND",
                PriorResponse = "BIND_ACK",
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
        Structure =
        [
            new OracleStructureRuleConfig
            {
                Id = "ai-min-header",
                Type = "minSize",
                Bytes = 8,
                OnlyWhenAccepted = true,
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
        Resource =
        [
            new OracleResourceRuleConfig
            {
                Id = "ai-response-cap",
                Type = "maxResponseBytes",
                MaxBytes = 1_048_576,
                Experimental = true,
                Severity = "nearMiss",
            },
            new OracleResourceRuleConfig
            {
                Id = "ai-expansion-ratio",
                Type = "responseToPayloadRatio",
                MaxRatio = 64,
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
        Metamorphic =
        [
            new OracleMetamorphicRuleConfig
            {
                Id = "ai-ws-insensitive",
                Type = "whitespaceInsensitive",
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
    };

    /// <summary>
    /// Optional experimental pack (auth + length-prefix). Not auto-merged —
    /// call only when the project enables auth / modeled length fields.
    /// </summary>
    public static OracleConfig CreateExperimentalAuthAndLength() => new()
    {
        AuthEnabled = true,
        Auth =
        [
            new OracleAuthRuleConfig
            {
                Id = "ai-no-success-before-auth",
                Type = "forbidUntil",
                ForbidResponse = "OK",
                UntilResponse = "AUTH",
                Experimental = true,
                Severity = "nearMiss",
            },
            new OracleAuthRuleConfig
            {
                Id = "ai-no-rpc-ok-before-bind",
                Type = "forbidUntil",
                ForbidResponse = "RPC_OK",
                UntilResponse = "BIND_ACK",
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
        Integer =
        [
            new OracleIntegerRuleConfig
            {
                Id = "ai-length-prefix",
                Type = "lengthPrefix",
                Offset = 0,
                Width = 4,
                Endian = "le",
                Covers = "rest",
                MaxPlausible = 1_048_576,
                Modeled = true,
                Experimental = true,
                Severity = "nearMiss",
            },
        ],
    };

    /// <summary>
    /// Merge AI pack into an existing config without wiping user rules.
    /// Empty sections get pack defaults; enabled is forced on.
    /// Never injects auth or unmodeled length-prefix rules.
    /// </summary>
    public static OracleConfig MergeInto(OracleConfig? existing)
    {
        var pack = Create();
        if (existing is null)
            return pack;

        existing.Enabled = true;
        existing.RetainOnViolation = true;
        existing.PersistFindings = true;
        // Do not force AuthEnabled — project must opt in.
        // Do not merge Auth / Integer from AI pack (false positives on text protocols).
        if (existing.State.Count == 0)
            existing.State = pack.State;
        if (existing.Structure.Count == 0)
            existing.Structure = pack.Structure;
        if (existing.Resource.Count == 0)
            existing.Resource = pack.Resource;
        if (existing.Metamorphic.Count == 0)
            existing.Metamorphic = pack.Metamorphic;
        return existing;
    }

    public static IReadOnlyList<string> RecommendedMutators() =>
        ["dictionary", "interesting", "boundary", "havoc", "expand", "insert", "arith"];
}
