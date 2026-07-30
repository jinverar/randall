namespace Randall.Contracts;

/// <summary>
/// Integrity of the crash ↔ dump ↔ process ↔ input join before strong research promotion.
/// </summary>
public enum ArtifactIntegrityStatus
{
    /// <summary>All hard identity checks passed.</summary>
    Verified,
    /// <summary>Hard checks passed; soft mismatches need human review (e.g. unexpected managed modules).</summary>
    VerifiedWithWarnings,
    /// <summary>Legacy / incomplete identity envelope — do not treat as Verified.</summary>
    Unverified,
    /// <summary>
    /// Hard mismatch or failed dump claim. Crash stays collectible/visible but must not enter
    /// root-cause / primitive / genealogy / twin / stronger Court confirmation.
    /// </summary>
    Rejected,
}

/// <summary>Transactional dump-slot lifecycle (flat-file reservation under dumps/).</summary>
public enum DumpReservationState
{
    Armed,
    Triggered,
    DumpMaterialized,
    Claimed,
    Validated,
    Expired,
    Rejected,
}

/// <summary>Teardown / secondary-exception classification for promotion gating.</summary>
public enum SecondaryExceptionKind
{
    None,
    /// <summary>Fault site is process teardown (NtTerminateProcess / ExitProcess / …).</summary>
    Teardown,
    /// <summary>Observed fault looks like a secondary exception dominating the dump.</summary>
    SecondaryException,
}

/// <summary>
/// Immutable envelope tying one crash to one target generation, input, and dump claim.
/// Every crash-related research object should carry or reference the same identity.
/// </summary>
public sealed record CrashArtifactIdentity(
    Guid CrashId,
    string RunId,
    Guid TargetGenerationId,
    long IterationId,
    string ProjectName,
    string InputSha256,
    string InputPath,
    string ExecutablePath,
    string ExecutableSha256,
    int ExpectedPid,
    DateTimeOffset ProcessStartTimeUtc,
    DateTimeOffset? SendStartedUtc,
    DateTimeOffset? SendCompletedUtc,
    DateTimeOffset? FailureObservedUtc,
    DateTimeOffset? DumpCreatedUtc,
    string? DumpPath,
    int? DumpPid,
    string? DumpProcessName,
    DateTimeOffset? DumpProcessStartTimeUtc,
    string AnalysisEngineVersion,
    string AnalysisEngineCommit,
    Guid? DumpReservationId = null,
    ArtifactIntegrityStatus IntegrityStatus = ArtifactIntegrityStatus.Unverified,
    SecondaryExceptionKind SecondaryException = SecondaryExceptionKind.None,
    TargetProcessAttestation? TargetAttestation = null,
    TargetProcessAttestation? DumpAttestation = null);

/// <summary>Process attestation captured at target start and (when available) from dump metadata.</summary>
public sealed record TargetProcessAttestation(
    int Pid,
    int? ParentPid,
    DateTimeOffset CreationTimeUtc,
    string ImagePath,
    string ImageSha256,
    uint? PeTimestamp,
    string? Arch,
    string? CommandLine,
    int? SessionId,
    IReadOnlyList<string> ModuleBaseline);

/// <summary>One dump-slot reservation for a target generation (claim-once).</summary>
public sealed record DumpReservationDto(
    Guid ReservationId,
    Guid TargetGenerationId,
    string ProjectName,
    int ExpectedPid,
    DateTimeOffset ProcessStartTimeUtc,
    string ExecutablePath,
    string ExecutableSha256,
    string? ArmedDumpPath,
    DumpReservationState State,
    DateTimeOffset ArmedAtUtc,
    DateTimeOffset? TriggeredAtUtc = null,
    DateTimeOffset? MaterializedAtUtc = null,
    DateTimeOffset? ClaimedAtUtc = null,
    Guid? ClaimedCrashId = null,
    long? ClaimedIterationId = null,
    string? MaterializedDumpPath = null,
    string? RejectReason = null);

/// <summary>Result of <c>ValidateIdentity</c> before analysis promotion.</summary>
public sealed record ArtifactValidationResult(
    ArtifactIntegrityStatus Status,
    CrashArtifactIdentity Identity,
    IReadOnlyList<string> HardFailures,
    IReadOnlyList<string> Warnings,
    DumpReservationState? ReservationState = null,
    SecondaryExceptionKind SecondaryException = SecondaryExceptionKind.None,
    string? Summary = null);

/// <summary>Live target generation stamped on each successful start/restart.</summary>
public sealed record TargetGenerationDto(
    Guid TargetGenerationId,
    string ProjectName,
    string RunId,
    int Pid,
    DateTimeOffset ProcessStartTimeUtc,
    string ExecutablePath,
    string ExecutableSha256,
    TargetProcessAttestation Attestation,
    Guid? DumpReservationId = null,
    DateTimeOffset StartedAtUtc = default);
