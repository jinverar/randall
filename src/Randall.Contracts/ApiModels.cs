namespace Randall.Contracts;

public static class RandallLegs
{
    public const string Model = "model";
    public const string Mutate = "mutate";
    public const string Send = "send";
    public const string Stalk = "stalk";
    public const string Scream = "scream";
    public const string Proxy = "proxy";
    public const string Web = "web";
    public const string Pack = "pack";

    public static readonly IReadOnlyList<(string Id, string Title, string Summary)> All =
    [
        (Model, "Leg 1 — Model", "Block-based protocol definitions"),
        (Mutate, "Leg 2 — Mutate", "Field-aware mutation strategies"),
        (Send, "Leg 3 — Send", "TCP, UDP, file, and stdin transports"),
        (Stalk, "Leg 4 — Stalk", "DynamoRIO coverage and frontier detection"),
        (Scream, "Leg 5 — Scream", "Crash capture, dedup, and replay"),
        (Proxy, "Leg 6 — Proxy", "MITM capture and live traffic editing"),
        (Web, "Leg 7 — Web", "Browser UI and remote lab agent"),
        (Pack, "Leg 8 — Pack", "Standalone portable project bundles"),
    ];
}

public sealed record LegInfoDto(string Id, string Title, string Summary);

public sealed record HealthDto(string Name, string Version, string Status);

/// <summary>
/// OS platform vocabulary shared by the doctor, UI preferences, and tool discovery.
/// <c>windows</c>/<c>linux</c> scope tool-specific behavior; <c>cross</c> marks checks/options
/// that apply everywhere; <c>auto</c> (selection only) resolves to the host OS.
/// </summary>
public static class PlatformScope
{
    public const string Windows = "windows";
    public const string Linux = "linux";
    public const string Cross = "cross";
    public const string Auto = "auto";

    /// <summary>Values a user may pick in the platform selector.</summary>
    public static readonly IReadOnlyList<string> Selectable = [Auto, Windows, Linux];

    public static bool IsSelectable(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        Selectable.Contains(value.Trim().ToLowerInvariant());

    /// <summary>True when a check/option tagged <paramref name="scope"/> is visible for <paramref name="resolved"/>.</summary>
    public static bool VisibleFor(string scope, string resolved) =>
        string.Equals(scope, Cross, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(scope, resolved, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Host OS plus the currently resolved fuzzing platform (for the UI selector).</summary>
public sealed record PlatformInfoDto(string Host, string Resolved, IReadOnlyList<string> Selectable);

/// <summary>
/// Console UI preferences persisted under data/ui-prefs.json.
/// <c>Platform</c> is the user's chosen fuzzing platform (<c>auto</c>/<c>windows</c>/<c>linux</c>);
/// <c>HostPlatform</c> is server-computed (never persisted) so the UI knows the real host OS.
/// </summary>
public sealed record UiPrefsDto(
    string Theme = "light",
    string Platform = "auto",
    string? HostPlatform = null,
    bool ScreamCanisters = true,
    bool ScreamAnimations = false);

public sealed record UiPrefsUpdateRequest(
    string? Theme = null,
    string? Platform = null,
    bool? ScreamCanisters = null,
    bool? ScreamAnimations = null);

public sealed record FuzzStartRequest(
    string ConfigPath,
    bool DryRun = false,
    bool CoverageGuided = false,
    int? MaxIterations = null,
    string? DebuggerMode = null,
    string? DebuggerKind = null,
    bool? DebuggerOpenOnCrash = null,
    bool? ProcmonCapture = null,
    bool? TcpvconCapture = null,
    bool? ProcdumpOnCrash = null,
    bool? PktmonCapture = null,
    bool? TsharkCapture = null,
    bool? EtwCapture = null,
    bool? DebugViewCapture = null,
    bool? SysinternalsSnapshots = null,
    bool? StringsOnCrash = null);

public sealed record FuzzSessionStatusDto(
    bool Running,
    string Phase,
    string? ConfigPath,
    int Iterations,
    int Crashes,
    int CorpusAdded,
    int CoverageEdges,
    bool? CoverageGuided,
    string? LastMessage,
    int? TargetPid = null,
    string? DebuggerMode = null);

/// <summary>One recorder stopped during fuzz teardown or <c>randall recorders stop</c>.</summary>
public sealed record RecordingStopItemDto(string Name, string? Path, string Status);

/// <summary>Result of stopping armed / orphaned Sysinternals + Windows captures.</summary>
public sealed record RecordingStopResultDto(
    bool Ok,
    string Message,
    IReadOnlyList<RecordingStopItemDto> Items);

public sealed record CorpusStatsDto(
    string Project,
    int SeedFiles,
    int SeenInputs,
    int CoverageEdges,
    bool DynamoRioAvailable);
