using System.Diagnostics;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public sealed class FuzzEngine
{
    public async Task<FuzzRunResult> RunAsync(
        ProjectConfig project,
        string yamlPath,
        bool dryRun = false,
        CancellationToken cancellationToken = default)
    {
        var mutators = BuiltInMutators.Create(project.Mutators);
        var seeds = LoadAllSeeds(project, yamlPath);
        if (seeds.Count == 0)
            seeds.Add(Array.Empty<byte>());

        var crashStore = new CrashStore(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir));
        crashStore.Ensure();
        Directory.CreateDirectory(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir));

        var crashes = new List<CrashRecord>();
        Process? longLived = null;
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
            longLived = TargetRunner.StartTarget(project, yamlPath, null);

        var iterations = 0;
        var crashCount = 0;
        var rng = Random.Shared;

        try
        {
            for (var i = 0; i < project.Fuzz.MaxIterations && !cancellationToken.IsCancellationRequested; i++)
            {
                iterations++;
                var seed = seeds[rng.Next(seeds.Count)];
                var mutator = mutators[rng.Next(mutators.Count)];
                var payload = mutator.Mutate(seed).ToArray();
                if (project.Transport.Prefix.Length > 0)
                {
                    var prefix = Encoding.ASCII.GetBytes(project.Transport.Prefix);
                    payload = prefix.Concat(payload).ToArray();
                }

                if (dryRun)
                {
                    Console.WriteLine($"[dry-run] #{iterations} {mutator.Name} len={payload.Length}");
                    continue;
                }

                var result = await TargetRunner.RunPayloadAsync(
                    project, yamlPath, payload, longLived, cancellationToken);

                if (result.Crashed)
                {
                    crashCount++;
                    var saved = crashStore.Save(
                        project.Name, iterations, mutator.Name, payload, result.ExitCode, result.MiniDumpPath);
                    Console.WriteLine(
                        $"CRASH #{crashCount} iter={iterations} mutator={mutator.Name} " +
                        $"detail={result.Detail} saved={saved.InputPath}" +
                        (saved.MiniDumpPath is not null ? $" dump={saved.MiniDumpPath}" : ""));
                    crashes.Add(new CrashRecord(
                        saved.Id,
                        payload,
                        saved.InputHash,
                        result.ExitCode?.ToString() ?? result.Detail,
                        null,
                        saved.MiniDumpPath,
                        0));

                    if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
                    {
                        longLived?.Kill(entireProcessTree: true);
                        longLived?.Dispose();
                        await Task.Delay(300, cancellationToken);
                        longLived = TargetRunner.StartTarget(project, yamlPath, null);
                    }
                }
                else if (iterations % 50 == 0)
                {
                    Console.WriteLine($"iter={iterations} ok len={payload.Length}");
                }
            }
        }
        finally
        {
            if (longLived is { HasExited: false })
            {
                longLived.Kill(entireProcessTree: true);
                longLived.Dispose();
            }
        }

        return new FuzzRunResult(iterations, 0, crashCount, crashes);
    }

    private static List<byte[]> LoadAllSeeds(ProjectConfig project, string yamlPath)
    {
        var list = new List<byte[]>();
        foreach (var seed in project.Seeds)
        {
            try
            {
                list.Add(ProjectLoader.LoadSeed(yamlPath, seed));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: skip seed {seed}: {ex.Message}");
            }
        }
        return list;
    }
}
