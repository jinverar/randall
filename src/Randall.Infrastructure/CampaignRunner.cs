using Randall.Contracts;
using Randall.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Randall.Infrastructure;

public static class CampaignLoader
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static CampaignConfig Load(string yamlPath)
    {
        var full = Path.GetFullPath(yamlPath);
        var yaml = File.ReadAllText(full);
        var config = Deserializer.Deserialize<CampaignConfig>(yaml)
            ?? throw new InvalidOperationException($"Failed to parse campaign: {full}");
        config.Name = string.IsNullOrWhiteSpace(config.Name)
            ? Path.GetFileNameWithoutExtension(full)
            : config.Name;
        return config;
    }

    public static IEnumerable<string> Discover(string campaignsDir)
    {
        if (!Directory.Exists(campaignsDir))
            yield break;
        foreach (var f in Directory.EnumerateFiles(campaignsDir, "*.yaml"))
            yield return f;
        foreach (var f in Directory.EnumerateFiles(campaignsDir, "*.yml"))
            yield return f;
    }
}

public sealed class CampaignRunner
{
    public async Task<CampaignResultDto> RunAsync(
        CampaignConfig campaign,
        string campaignYamlPath,
        IFuzzProgressSink? progress = null,
        CancellationToken cancellationToken = default)
    {
        var repoRoot = CrashCatalog.FindRepoRoot()
            ?? Path.GetDirectoryName(Path.GetFullPath(campaignYamlPath))
            ?? Directory.GetCurrentDirectory();

        var results = new List<CampaignRunResult>();
        var totalCrashes = 0;

        foreach (var run in campaign.Runs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var projectPath = Path.IsPathRooted(run.Project)
                ? run.Project
                : Path.GetFullPath(Path.Combine(repoRoot, run.Project));

            try
            {
                var project = ProjectLoader.Load(projectPath);
                if (run.MaxIterations > 0)
                    project.Fuzz.MaxIterations = run.MaxIterations;

                progress?.OnStarted(project.Name, $"campaign:{campaign.Name}");
                var engine = new FuzzEngine();
                var result = await engine.RunAsync(
                    project,
                    projectPath,
                    new FuzzRunOptions(run.DryRun, run.CoverageGuided, run.MaxIterations, progress),
                    cancellationToken);

                totalCrashes += result.CrashesFound;
                results.Add(new CampaignRunResult(
                    project.Name,
                    result.Iterations,
                    result.CrashesFound,
                    result.CorpusAdded,
                    true,
                    null));
            }
            catch (Exception ex)
            {
                results.Add(new CampaignRunResult(
                    Path.GetFileNameWithoutExtension(run.Project),
                    0, 0, 0, false, ex.Message));
            }
        }

        return new CampaignResultDto(campaign.Name, results.All(r => r.Success), results, totalCrashes);
    }
}

public sealed class CampaignSessionManager
{
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _task;
    private CampaignStatusDto _status = new(false, "idle", null, 0, 0, 0, null);

    public CampaignStatusDto Status
    {
        get { lock (_gate) return _status; }
    }

    public bool Start(string campaignPath, IFuzzProgressSink? sink = null)
    {
        lock (_gate)
        {
            if (_task is { IsCompleted: false })
                return false;

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            var fullPath = Path.GetFullPath(campaignPath);
            var campaign = CampaignLoader.Load(fullPath);
            _status = new CampaignStatusDto(true, "running", fullPath, 0, campaign.Runs.Count, 0, "Starting…");

            _task = Task.Run(async () =>
            {
                try
                {
                    var runner = new CampaignRunner();
                    var result = await runner.RunAsync(campaign, fullPath, sink, token);
                    lock (_gate)
                    {
                        _status = _status with
                        {
                            Running = false,
                            Phase = "completed",
                            CompletedRuns = result.Runs.Count,
                            TotalCrashes = result.TotalCrashes,
                            LastMessage = $"Done — {result.TotalCrashes} crashes across {result.Runs.Count} runs",
                        };
                    }
                }
                catch (OperationCanceledException)
                {
                    lock (_gate)
                    {
                        _status = _status with { Running = false, Phase = "stopped", LastMessage = "Cancelled" };
                    }
                }
                catch (Exception ex)
                {
                    lock (_gate)
                    {
                        _status = _status with { Running = false, Phase = "error", LastMessage = ex.Message };
                    }
                }
            }, token);
            return true;
        }
    }

    public bool Stop()
    {
        lock (_gate)
        {
            _cts?.Cancel();
            _status = _status with { Phase = "stopping", LastMessage = "Stopping…" };
            return _cts is not null;
        }
    }
}
