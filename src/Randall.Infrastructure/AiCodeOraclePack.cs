using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Default semantic-oracle pack aimed at common AI-codegen bugs
/// (auth skips, state order, length lies, structure trust, resource abuse).
/// </summary>
public static class AiCodeOraclePack
{
    public const string DictionaryRelativePath = "dictionaries/ai_codegen_mistakes.txt";

    /// <summary>Build a fresh oracle config tuned for AI mistakes.</summary>
    public static OracleConfig Create() => new()
    {
        Enabled = true,
        RetainOnViolation = true,
        RetainOnNearMiss = true,
        PersistFindings = true,
        PromoteExpectResponse = true,
        PromotePostReceiveAbort = true,
        InvariantSeverity = "violation",
        Auth =
        [
            new OracleAuthRuleConfig
            {
                Id = "ai-no-success-before-auth",
                Type = "forbidUntil",
                ForbidResponse = "OK",
                UntilResponse = "AUTH",
                Severity = "violation",
            },
            new OracleAuthRuleConfig
            {
                Id = "ai-no-rpc-ok-before-bind",
                Type = "forbidUntil",
                ForbidResponse = "RPC_OK",
                UntilResponse = "BIND_ACK",
                Severity = "violation",
            },
        ],
        State =
        [
            new OracleStateRuleConfig
            {
                Id = "ai-request-needs-bind",
                Type = "commandRequiresPrior",
                ForCommand = "REQUEST",
                PriorCommand = "BIND",
                PriorResponse = "BIND_ACK",
                Severity = "violation",
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
                Severity = "violation",
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
                Severity = "violation",
            },
            new OracleResourceRuleConfig
            {
                Id = "ai-expansion-ratio",
                Type = "responseToPayloadRatio",
                MaxRatio = 64,
                Severity = "nearMiss",
            },
        ],
        Metamorphic =
        [
            new OracleMetamorphicRuleConfig
            {
                Id = "ai-ws-insensitive",
                Type = "whitespaceInsensitive",
                Severity = "nearMiss",
            },
        ],
    };

    /// <summary>
    /// Merge AI pack into an existing config without wiping user rules.
    /// Empty sections get pack defaults; enabled is forced on.
    /// </summary>
    public static OracleConfig MergeInto(OracleConfig? existing)
    {
        var pack = Create();
        if (existing is null)
            return pack;

        existing.Enabled = true;
        existing.RetainOnViolation = true;
        existing.PersistFindings = true;
        if (existing.Auth.Count == 0)
            existing.Auth = pack.Auth;
        if (existing.State.Count == 0)
            existing.State = pack.State;
        if (existing.Integer.Count == 0)
            existing.Integer = pack.Integer;
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
