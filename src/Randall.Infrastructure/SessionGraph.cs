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
        string? ModelPath,
        string? ExpectResponse);

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
                cmd.Model,
                cmd.ExpectResponse));
        }
        return list;
    }

    public static byte[] BuildPayload(PreparedCommand command, byte[] mutatedBody) =>
        command.Prefix.Concat(mutatedBody).ToArray();

    public sealed record PreparedFlow(string Name, IReadOnlyList<PreparedCommand> Steps, string MutateStep = "");

    public static IReadOnlyList<PreparedFlow> LoadFlows(
        ProjectConfig project,
        string yamlPath,
        IReadOnlyList<PreparedCommand> commands)
    {
        if (project.SessionFlows.Count == 0)
            return [];

        var byName = commands.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var flows = new List<PreparedFlow>();
        foreach (var flow in project.SessionFlows)
        {
            if (flow.Steps.Count == 0)
                continue;
            var steps = new List<PreparedCommand>();
            foreach (var step in flow.Steps)
            {
                if (byName.TryGetValue(step, out var cmd))
                    steps.Add(cmd);
            }
            if (steps.Count > 0)
                flows.Add(new PreparedFlow(
                    string.IsNullOrWhiteSpace(flow.Name) ? string.Join("→", flow.Steps) : flow.Name,
                    steps,
                    flow.MutateStep));
        }
        return flows;
    }

    public static byte[] BuildBaseline(PreparedCommand command, string yamlPath)
    {
        if (!string.IsNullOrWhiteSpace(command.ModelPath))
        {
            var model = ProtocolLoader.Load(yamlPath, command.ModelPath);
            var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, command.ModelPath);
            return model.Render(protoSeeds);
        }
        return BuildPayload(command, command.Seed);
    }
}
