using System.Diagnostics;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

/// <summary>Leg 3 — Send: boofuzz s_switch — branch session steps on live server responses.</summary>
public static class ResponseGraphRunner
{
    public sealed record GraphRunResult(
        TargetRunResult Run,
        string PathLabel,
        byte[] LastPayload);

    public static async Task<GraphRunResult?> RunAsync(
        ProjectConfig project,
        string yamlPath,
        Process? server,
        IReadOnlyDictionary<string, SessionGraph.PreparedCommand> commands,
        SessionGraphConfig graph,
        IMutator mutator,
        Random rng,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(graph.Start) || !commands.TryGetValue(graph.Start, out _))
            return null;

        var mutateTarget = string.IsNullOrWhiteSpace(graph.Mutate)
            ? graph.Edges.LastOrDefault()?.To ?? graph.Start
            : graph.Mutate;

        var edgesByFrom = graph.Edges
            .GroupBy(e => e.From, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var path = new List<string>();
        var current = graph.Start;
        byte[] lastPayload = [];
        byte[]? lastResponse = null;
        var visited = 0;
        const int maxHops = 16;

        try
        {
            await using var stream = await TcpTransport.ConnectAsync(project.Transport, cancellationToken);

            while (visited++ < maxHops && commands.TryGetValue(current, out var cmd))
            {
                path.Add(current);
                var mutate = current.Equals(mutateTarget, StringComparison.OrdinalIgnoreCase);
                lastPayload = FuzzEngineHelpers.BuildCommandPayload(
                    cmd, yamlPath, mutator, rng, mutate, project);

                if (path.Count == 1 && cmd.ReadBanner)
                {
                    lastResponse = await TcpTransport.ReadAvailableAsync(
                        stream, project.Transport.ReceiveTimeoutMs, cancellationToken);
                }

                if (cmd.Preamble is { Length: > 0 })
                {
                    await stream.WriteAsync(cmd.Preamble, cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    lastResponse = await TcpTransport.ReadAvailableAsync(
                        stream, project.Transport.ReceiveTimeoutMs, cancellationToken);
                }

                await stream.WriteAsync(lastPayload, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                lastResponse = await TcpTransport.ReadAvailableAsync(
                    stream, project.Transport.ReceiveTimeoutMs, cancellationToken);

                if (!ResponseMatcher.Matches(lastResponse, cmd.ExpectResponse))
                {
                    var run = new TargetRunResult(
                        false, null, null,
                        $"graph {current} expect={cmd.ExpectResponse} got={ResponseMatcher.Describe(lastResponse)}",
                        lastResponse);
                    return new GraphRunResult(run, string.Join("→", path), lastPayload);
                }

                if (mutate)
                    break;

                if (!edgesByFrom.TryGetValue(current, out var outs) || outs.Count == 0)
                    break;

                var next = outs.FirstOrDefault(e => ResponseMatcher.Matches(lastResponse, e.When))?.To;
                if (string.IsNullOrWhiteSpace(next))
                    break;
                current = next;
            }
        }
        catch (Exception ex)
        {
            return new GraphRunResult(
                new TargetRunResult(false, null, null, ex.Message, null),
                string.Join("→", path),
                lastPayload);
        }

        var finished = await TargetRunner.FinishTcpRunFromGraph(
            project, yamlPath, server, lastResponse, cancellationToken);
        return new GraphRunResult(finished, string.Join("→", path), lastPayload);
    }
}

/// <summary>Shared payload builder for graph runner.</summary>
public static class FuzzEngineHelpers
{
    public static byte[] BuildCommandPayload(
        SessionGraph.PreparedCommand cmd,
        string yamlPath,
        IMutator mutator,
        Random rng,
        bool mutate,
        ProjectConfig project)
    {
        if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
        {
            var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
            var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
            if (mutate)
                return ModelFuzzer.BuildPayload(
                    model, protoSeeds, mutator, rng,
                    project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth,
                    targetField: null, project.Fuzz.SyncNbssLength);
            var msg = model.FinalizeMessage(model.Render(protoSeeds), project.Fuzz.SyncLengthFields);
            return project.Fuzz.SyncNbssLength ? NbssFraming.TrySyncLength(msg) : msg;
        }

        var body = mutate ? mutator.Mutate(cmd.Seed).ToArray() : cmd.Seed;
        return SessionGraph.BuildPayload(cmd, body);
    }
}
