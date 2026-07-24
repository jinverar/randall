using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

/// <summary>
/// Oracle foresight — translates findings into needs the Magician can answer
/// (knight / army / bots / hunter / dictionary / energy). Judgment stays in OracleEngine;
/// this only asks for help.
/// </summary>
public static class OracleNeeds
{
    public static IReadOnlyList<OracleNeedDto> FromFindings(IReadOnlyList<OracleFindingDto> findings)
    {
        if (findings.Count == 0)
            return [];

        var needs = new List<OracleNeedDto>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string request, OracleFindingDto f, string reason)
        {
            var key = $"{request}:{f.RuleClass}:{f.RuleId}";
            if (!seen.Add(key))
                return;
            needs.Add(new OracleNeedDto(request, reason, f.RuleClass, f.RuleId, f.Severity));
        }

        foreach (var f in findings)
        {
            var cls = (f.RuleClass ?? "").ToLowerInvariant();
            var sev = (f.Severity ?? "").ToLowerInvariant();
            var isHard = sev is "violation" or "runtime";

            // Always ask for energy boost on interesting findings so Magician can follow up.
            Add("energy", f, $"Oracle saw {f.RuleClass}/{f.RuleId} — boost this input");

            switch (cls)
            {
                case "auth":
                case "state":
                    Add("dictionary", f, "Auth/state miss — more session tokens");
                    Add("hunter", f, "Likely AI-shaped logic bug — summon Bug Hunter");
                    if (isHard)
                        Add("bots", f, "Hard auth/state finding — summon analyst bots (AI seed hint)");
                    break;
                case "integer":
                case "structure":
                    Add("dictionary", f, "Structural lie — inject framing tokens");
                    Add("army", f, "Need wider mutator army on framing");
                    break;
                case "resource":
                    Add("army", f, "Resource signal — havoc/expand army");
                    break;
                case "differential":
                case "metamorphic":
                    Add("knight", f, "Semantic diverge — summon knight (stalk/coverage)");
                    Add("bots", f, "Compare path — analyst bots may mint better seeds");
                    break;
                case "invariant":
                    Add("dictionary", f, "Invariant miss — dictionary pressure");
                    if (isHard)
                        Add("rearm", f, "Hard invariant — re-arm oracle pack");
                    break;
                case "runtime":
                    Add("knight", f, "Crash/runtime — intensify stalking knight");
                    Add("army", f, "Crash — summon mutator army");
                    break;
                default:
                    if (isHard)
                        Add("army", f, $"Hard {f.RuleClass} finding — mutator army");
                    break;
            }
        }

        return needs;
    }
}
