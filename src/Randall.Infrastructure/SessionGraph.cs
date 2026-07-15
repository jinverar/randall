using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 1 — Model: Sulley-style session graph with optional block models.</summary>
public static class SessionGraph
{
    public sealed record PreparedCommand(
        string Name,
        byte[] Seed,
        byte[] Prefix,
        byte[]? Preamble,
        bool ReadBanner,
        string? ModelPath);

    public static IReadOnlyList<PreparedCommand> LoadCommands(ProjectConfig project, string yamlPath)
    {
        if (project.SessionCommands.Count == 0)
            return [];

        var list = new List<PreparedCommand>();
        foreach (var cmd in project.SessionCommands)
        {
            byte[] seed;
            if (!string.IsNullOrWhiteSpace(cmd.Seed))
            {
                try { seed = ProjectLoader.LoadSeed(yamlPath, cmd.Seed); }
                catch { seed = Encoding.ASCII.GetBytes("AAAA"); }
            }
            else
            {
                seed = Encoding.ASCII.GetBytes("AAAA");
            }

            list.Add(new PreparedCommand(
                string.IsNullOrWhiteSpace(cmd.Name) ? cmd.Prefix : cmd.Name,
                seed,
                Encoding.ASCII.GetBytes(cmd.Prefix),
                string.IsNullOrWhiteSpace(cmd.Preamble) ? null : Encoding.ASCII.GetBytes(cmd.Preamble),
                cmd.ReadBanner,
                cmd.Model));
        }
        return list;
    }

    public static byte[] BuildPayload(PreparedCommand command, byte[] mutatedBody) =>
        command.Prefix.Concat(mutatedBody).ToArray();
}
