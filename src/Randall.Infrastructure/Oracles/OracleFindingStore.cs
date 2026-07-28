using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

public sealed class OracleFindingStore(string findingsDir)
{
    private readonly string _indexPath = Path.Combine(findingsDir, "oracle_findings.jsonl");
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    private readonly object _gate = new();

    public void Ensure() => Directory.CreateDirectory(findingsDir);

    /// <summary>Append-only (legacy). Prefer <see cref="AppendOrAggregate"/> for semantic clustering.</summary>
    public void Append(OracleFindingDto finding)
    {
        Ensure();
        File.AppendAllText(_indexPath, JsonSerializer.Serialize(finding, JsonOpts) + Environment.NewLine);
    }

    /// <summary>
    /// Cluster by rule + input hash (+ command): increment ReproductionCount instead of
    /// emitting duplicate rows for the same semantic finding.
    /// </summary>
    public OracleFindingDto AppendOrAggregate(OracleFindingDto finding)
    {
        Ensure();
        lock (_gate)
        {
            var existing = List().ToList();
            var idx = existing.FindIndex(f => SameCluster(f, finding));
            if (idx < 0)
            {
                File.AppendAllText(_indexPath, JsonSerializer.Serialize(finding, JsonOpts) + Environment.NewLine);
                return finding;
            }

            var prev = existing[idx];
            var updated = prev with
            {
                ReproductionCount = Math.Max(1, prev.ReproductionCount) + 1,
                Iteration = finding.Iteration,
                At = finding.At,
                OracleScoreTotal = finding.OracleScoreTotal ?? prev.OracleScoreTotal,
                OracleScoreTerms = finding.OracleScoreTerms ?? prev.OracleScoreTerms,
                ActualRelation = finding.ActualRelation,
                NormalizedObservation = finding.NormalizedObservation ?? prev.NormalizedObservation,
                CoverageSignature = finding.CoverageSignature ?? prev.CoverageSignature,
                Confidence = Math.Max(prev.Confidence, finding.Confidence),
            };
            existing[idx] = updated;
            RewriteAll(existing);
            return updated;
        }
    }

    public IReadOnlyList<OracleFindingDto> List(string? project = null)
    {
        if (!File.Exists(_indexPath))
            return [];
        var list = new List<OracleFindingDto>();
        foreach (var line in File.ReadLines(_indexPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                var f = JsonSerializer.Deserialize<OracleFindingDto>(line);
                if (f is null)
                    continue;
                if (project is null || f.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
                    list.Add(f);
            }
            catch { /* skip bad lines */ }
        }
        return list;
    }

    private void RewriteAll(IReadOnlyList<OracleFindingDto> findings)
    {
        var tmp = _indexPath + ".tmp";
        using (var w = new StreamWriter(tmp, false))
        {
            foreach (var f in findings)
                w.WriteLine(JsonSerializer.Serialize(f, JsonOpts));
        }
        File.Copy(tmp, _indexPath, overwrite: true);
        try { File.Delete(tmp); } catch { /* ignore */ }
    }

    internal static bool SameCluster(OracleFindingDto a, OracleFindingDto b) =>
        a.Project.Equals(b.Project, StringComparison.OrdinalIgnoreCase) &&
        a.RuleId.Equals(b.RuleId, StringComparison.OrdinalIgnoreCase) &&
        a.InputHash.Equals(b.InputHash, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.Command ?? "", b.Command ?? "", StringComparison.OrdinalIgnoreCase);
}
