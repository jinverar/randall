namespace Randall.Infrastructure;

/// <summary>
/// Function/path novelty for file targets that emit path logs (e.g. ReelDeck via REELDECK_PATHLOG).
/// Supplements DynamoRIO edges when a target can name the stages it entered — matures stalking
/// on platforms without drcov.
/// </summary>
public sealed class PathCoverageSet(string statePath)
{
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    public int Total => _seen.Count;

    public void Load()
    {
        var dir = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        if (!File.Exists(statePath))
            return;
        foreach (var line in File.ReadLines(statePath))
        {
            var t = line.Trim();
            if (t.Length > 0)
                _seen.Add(t);
        }
    }

    /// <summary>Returns count of newly observed path names.</summary>
    public int Add(IEnumerable<string> hits)
    {
        var novel = 0;
        foreach (var h in hits)
        {
            var t = h.Trim();
            if (t.Length == 0)
                continue;
            if (_seen.Add(t))
                novel++;
        }

        if (novel > 0)
            Persist();
        return novel;
    }

    public void Persist()
    {
        var dir = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllLines(statePath, _seen.OrderBy(x => x, StringComparer.Ordinal));
    }
}
