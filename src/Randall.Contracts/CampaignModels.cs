namespace Randall.Contracts;

public sealed class CampaignConfig
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public List<CampaignRunConfig> Runs { get; set; } = [];
}

public sealed class CampaignRunConfig
{
    public string Project { get; set; } = "";
    public int MaxIterations { get; set; } = 500;
    public bool DryRun { get; set; }
    public bool CoverageGuided { get; set; }
}

public sealed record CampaignRunResult(
    string Project,
    int Iterations,
    int Crashes,
    int CorpusAdded,
    bool Success,
    string? Error);

public sealed record CampaignResultDto(
    string Name,
    bool Success,
    IReadOnlyList<CampaignRunResult> Runs,
    int TotalCrashes);

public sealed record CampaignStatusDto(
    bool Running,
    string Phase,
    string? CampaignPath,
    int CompletedRuns,
    int TotalRuns,
    int TotalCrashes,
    string? LastMessage);

public sealed record CampaignStartRequest(string CampaignPath);

public sealed class RppPluginManifest
{
    public string Name { get; set; } = "";
    public string Runtime { get; set; } = "python";
    public string Entry { get; set; } = "";
    public string Hook { get; set; } = "mutate";
}

public sealed class PluginRefConfig
{
    public string Path { get; set; } = "";
    public string Hook { get; set; } = "mutate";
}

public sealed record PluginInfoDto(
    string Name,
    string Runtime,
    string Hook,
    string ManifestPath);

public sealed record PackResultDto(
    string OutputPath,
    long SizeBytes,
    string[] Included);

public sealed record BundleResultDto(string Path, string Action, long? SizeBytes);
