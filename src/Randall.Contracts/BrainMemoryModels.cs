namespace Randall.Contracts;

public sealed record BrainMemoryStateDto(
    string? TargetBinaryHash,
    string? TargetBinaryPath,
    double MemoryConfidence,
    string? DecayMessage,
    string LastCheckedAt,
    int DecayCount);

public sealed record BrainMemoryCheckResult(
    double MemoryConfidence,
    string? DecayMessage,
    bool BinaryChanged,
    string? TargetBinaryHash,
    string? LogLine);
