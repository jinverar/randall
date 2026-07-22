using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

public sealed class OracleFindingStore(string findingsDir)
{
    private readonly string _indexPath = Path.Combine(findingsDir, "oracle_findings.jsonl");
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    public void Ensure() => Directory.CreateDirectory(findingsDir);

    public void Append(OracleFindingDto finding)
    {
        Ensure();
        File.AppendAllText(_indexPath, JsonSerializer.Serialize(finding, JsonOpts) + Environment.NewLine);
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
}
