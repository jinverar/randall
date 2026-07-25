using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CrashCanisterContextTests
{
    [Fact]
    public void Build_FusesRipFunctionOracleAndFrontier()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "canister-ctx-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, FrontierEngine.FileName),
                """
                {
                  "project": "x",
                  "scoredAt": "2026-01-01T00:00:00Z",
                  "mode": "cfg",
                  "summary": "1 door",
                  "coverageBlockCount": 1,
                  "frontierCount": 1,
                  "frontiers": [
                    {
                      "edgeKey": "k",
                      "kind": "cfg-branch",
                      "score": 77,
                      "cfgDistance": 1,
                      "rarity": 0.5,
                      "unseenSuccessorCount": 1,
                      "sinkProximity": 0.8,
                      "functionName": "parse_request",
                      "fromAddress": "0x401000",
                      "toAddress": "0x401010",
                      "detail": "gap"
                    }
                  ],
                  "workflowHint": ""
                }
                """);

            var summary = new CrashSummaryDto(
                Guid.NewGuid(), project, 1, "m", "h", "f.bin",
                null, null, null, null, null, DateTimeOffset.UtcNow);
            var triage = new CrashTriageDto(
                "access_violation", "high", "av", true, false, "k",
                "AV", "0xDEAD", null, "0x401020", null, null, null,
                new StaticFunctionMappingDto(
                    "rip", "0x401020", "parse_request", "+0xA", "ghidra", "0x1020", "calls memcpy", 88));
            var sidecar = new CrashSidecarDto(
                summary.Id, "run", 1, project, "cmd", "havoc", [], null, null, [], "h", "f.bin",
                64, -1, "AV", null, null, 2, 50, null, null, null, null, null, null, null,
                DateTimeOffset.UtcNow, null,
                new OracleScore(72, [new OracleScoreTerm("crash", 60, "AV")], "+60 crash"));

            var intel = CrashIntelligenceBuilder.Build(
                summary, triage, sidecar, 64, [summary], repoRoot: root);

            Assert.Contains("RIP 0x401020", intel.CanisterContext);
            Assert.Contains("parse_request+0xA", intel.CanisterContext!);
            Assert.Contains("oracle 72", intel.CanisterContext!);
            Assert.Contains("gray door", intel.FrontierHint!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
