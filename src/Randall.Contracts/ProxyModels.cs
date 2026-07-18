namespace Randall.Contracts;

public sealed record CapturedMessageDto(
    Guid Id,
    string Direction,
    DateTimeOffset At,
    int Length,
    string HexPreview,
    string? CommandTag);

/// <summary>Full payload for Scare Floor import / replay edit.</summary>
public sealed record CapturedMessageDetailDto(
    Guid Id,
    string Direction,
    DateTimeOffset At,
    int Length,
    string HexFull,
    string AsciiPreview,
    string? CommandTag);

public sealed record ProxyStartRequest(
    string TargetHost = "127.0.0.1",
    int TargetPort = 9999,
    int ListenPort = 9998,
    string? Tag = null);

public sealed record ProxyStatusDto(
    bool Running,
    int ListenPort,
    string TargetHost,
    int TargetPort,
    int MessageCount,
    string? LastMessage);

public sealed record ProxyReplayRequest(
    Guid MessageId,
    string? EditedHex = null);

public sealed record TriageBundleDto(
    Guid CrashId,
    string Project,
    string InputPath,
    string? MiniDumpPath,
    string? DrcovPath,
    int? FirstDivergeIndex,
    string ExportPath);
