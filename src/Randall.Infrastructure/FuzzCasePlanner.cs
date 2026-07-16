using Randall.Contracts;
using Randall.Core;
using Randall.Core.Model;

namespace Randall.Infrastructure;

/// <summary>Boofuzz-style exhaustive case walk: command × field × mutator.</summary>
public static class FuzzCasePlanner
{
    public sealed record FuzzCase(
        string Label,
        SessionGraph.PreparedCommand? Command,
        SessionGraph.PreparedFlow? Flow,
        int FlowStepIndex,
        FieldRegion? TargetField,
        IMutator Mutator);

    public static bool IsExhaustive(ProjectConfig project) =>
        project.Fuzz.Mode.Equals("exhaustive", StringComparison.OrdinalIgnoreCase);

    public static IEnumerable<FuzzCase> PlanCases(
        ProjectConfig project,
        string yamlPath,
        IReadOnlyList<IMutator> mutators,
        IReadOnlyList<SessionGraph.PreparedCommand> commands,
        IReadOnlyList<SessionGraph.PreparedFlow> flows)
    {
        if (commands.Count == 0 && string.IsNullOrWhiteSpace(project.Model))
            yield break;

        if (commands.Count == 0 && !string.IsNullOrWhiteSpace(project.Model))
        {
            var model = ProtocolLoader.Load(yamlPath, project.Model);
            var seeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, project.Model);
            foreach (var c in PlanModelCases($"model/{model.Name}", model, seeds, mutators))
                yield return c with { Command = null, Flow = null };
            yield break;
        }

        foreach (var cmd in commands)
        {
            if (string.IsNullOrWhiteSpace(cmd.ModelPath))
            {
                foreach (var mutator in mutators)
                    yield return new FuzzCase(cmd.Name, cmd, null, -1, null, mutator);
                continue;
            }

            var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
            var seeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
            foreach (var c in PlanModelCases(cmd.Name, model, seeds, mutators))
                yield return c with { Command = cmd, Flow = null };
        }

        foreach (var flow in flows)
        {
            var mutateSteps = MutateStepResolver.Resolve(
                flow.MutateStep,
                project.Fuzz.MutateStep,
                flow.Steps.Count);

            foreach (var stepIndex in mutateSteps)
            {
                var cmd = flow.Steps[stepIndex];
                if (string.IsNullOrWhiteSpace(cmd.ModelPath))
                {
                    foreach (var mutator in mutators)
                    {
                        yield return new FuzzCase(
                            $"flow/{flow.Name}/{cmd.Name}",
                            cmd,
                            flow,
                            stepIndex,
                            null,
                            mutator);
                    }
                    continue;
                }

                var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
                var seeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
                foreach (var c in PlanModelCases($"{flow.Name}/{cmd.Name}", model, seeds, mutators))
                {
                    yield return c with
                    {
                        Command = cmd,
                        Flow = flow,
                        FlowStepIndex = stepIndex,
                    };
                }
            }
        }
    }

    private static IEnumerable<FuzzCase> PlanModelCases(
        string prefix,
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IReadOnlyList<IMutator> mutators)
    {
        model.Render(seeds);
        var fields = model.GetMutableFields();
        if (fields.Count == 0)
        {
            foreach (var mutator in mutators)
                yield return new FuzzCase(prefix, null, null, -1, null, mutator);
            yield break;
        }

        foreach (var field in fields)
        foreach (var mutator in mutators)
            yield return new FuzzCase($"{prefix}/{field.Name}", null, null, -1, field, mutator);
    }
}

public static class MutateStepResolver
{
    public static IReadOnlyList<int> Resolve(string flowOverride, string projectDefault, int stepCount)
    {
        var spec = string.IsNullOrWhiteSpace(flowOverride) ? projectDefault : flowOverride;
        if (stepCount <= 0)
            return [];

        if (spec.Equals("all", StringComparison.OrdinalIgnoreCase))
            return Enumerable.Range(0, stepCount).ToList();

        if (spec.Equals("last", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(spec))
            return [stepCount - 1];

        var indices = new List<int>();
        foreach (var part in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out var idx) && idx >= 0 && idx < stepCount)
                indices.Add(idx);
        }
        return indices.Count > 0 ? indices : [stepCount - 1];
    }
}
