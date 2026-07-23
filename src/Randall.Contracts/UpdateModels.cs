namespace Randall.Contracts;

/// <summary>Signed update manifest (release metadata + per-RID asset hashes).</summary>
public sealed class UpdateManifestDto
{
    public int SchemaVersion { get; set; } = 1;
    public string Product { get; set; } = "randfuzz";
    public string Version { get; set; } = "";
    public string Channel { get; set; } = "stable";
    /// <summary>major | minor | patch — releaser hint for notification severity.</summary>
    public string Severity { get; set; } = "minor";
    public string? PublishedAt { get; set; }
    public string? NotesUrl { get; set; }
    public string? ReleaseTag { get; set; }
    public List<UpdateAssetDto> Assets { get; set; } = [];
}

public sealed class UpdateAssetDto
{
    public string Rid { get; set; } = "";
    public string File { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public string? ContentType { get; set; }
}

public sealed record UpdateCheckResultDto(
    bool Ok,
    string Message,
    string CurrentVersion,
    string? LatestVersion,
    bool UpdateAvailable,
    bool MajorUpdate,
    bool SignatureValid,
    string? NotesUrl,
    string? Channel,
    string? Severity,
    string InstallMode,          // portable | source | unknown
    string? MatchedAssetFile,
    string? MatchedAssetSha256,
    long? MatchedAssetSize,
    DateTimeOffset CheckedAt,
    IReadOnlyList<string>? Findings = null);

public sealed record UpdateApplyResultDto(
    bool Ok,
    string Message,
    string? AppliedVersion = null,
    string? StagingPath = null,
    string? FinishScript = null,
    bool RestartRequired = false,
    IReadOnlyList<string>? Steps = null);

public sealed record UpdateStatusDto(
    string CurrentVersion,
    string InstallMode,
    string? LastCheckedVersion,
    DateTimeOffset? LastCheckedAt,
    bool UpdateAvailable,
    bool MajorUpdate,
    bool SignatureValid,
    string? NotesUrl,
    string? DismissedVersion,
    bool BannerSuppressed,
    string? Message);

public sealed record UpdateDismissRequest(string? Version = null);
