using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Magician;

/// <summary>Append-only spell cast log under crashes/_magician/.</summary>
public sealed class MagicianSpellStore(string directory)
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private readonly string _path = Path.Combine(directory, "spells.jsonl");

    public void Append(MagicianSpellDto spell)
    {
        Directory.CreateDirectory(directory);
        File.AppendAllText(_path, JsonSerializer.Serialize(spell, JsonOpts) + Environment.NewLine);
    }

    public IReadOnlyList<MagicianSpellDto> List(string? projectFilter = null, int take = 500)
    {
        if (!File.Exists(_path))
            return [];

        var list = new List<MagicianSpellDto>();
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                var s = JsonSerializer.Deserialize<MagicianSpellDto>(line, JsonOpts);
                if (s is null)
                    continue;
                if (projectFilter is not null &&
                    !s.Project.Equals(projectFilter, StringComparison.OrdinalIgnoreCase))
                    continue;
                list.Add(s);
            }
            catch
            {
                /* skip bad line */
            }
        }

        return list.OrderByDescending(s => s.At).Take(take).ToList();
    }
}
