using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Crash artifact identity: target generation, dump reservation (claim-once), validation,
/// secondary-exception gating, and promotion blocks for Rejected / teardown-only dumps.
/// Flat-file store under <c>data/crashes/&lt;project&gt;/dumps/reservations/</c> — no database.
/// </summary>
public static class CrashArtifactIdentityService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly ConcurrentDictionary<string, object> ReservationLocks =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly Regex DumpPidRegex = new(
        @"(?:scream|procdump|wait|tcp)_(\d+)_",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> ManagedRuntimeModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "clrjit", "coreclr", "clr", "mscorlib", "System.Private.CoreLib",
        "hostfxr", "hostpolicy", "coreclr.dll", "clrjit.dll",
    };

    public static string ReservationsDir(string crashesDir) =>
        Path.Combine(crashesDir, "dumps", "reservations");

    public static string ReservationPath(string crashesDir, Guid reservationId) =>
        Path.Combine(ReservationsDir(crashesDir), $"{reservationId:N}.json");

    public static string IdentityPath(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_artifact_identity.json");

    public static string FileSha256(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return "";
        try
        {
            using var fs = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }

    public static string BytesSha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>Capture process attestation at successful target start.</summary>
    public static TargetProcessAttestation CaptureAttestation(Process proc, string? executablePath)
    {
        var image = FirstNonEmpty(executablePath, TryMainModulePath(proc), "")!;
        var sha = FileSha256(image);
        DateTimeOffset creation;
        try { creation = new DateTimeOffset(proc.StartTime.ToUniversalTime()); }
        catch { creation = DateTimeOffset.UtcNow; }

        string? arch = null;
        try
        {
            arch = Environment.Is64BitOperatingSystem
                ? (IsWow64(proc) ? "x86" : "x64")
                : "x86";
        }
        catch { /* ignore */ }

        string? cmdline = null;
        try { cmdline = Truncate(proc.StartInfo?.Arguments, 512); }
        catch { /* ignore */ }

        var modules = CaptureModuleBaseline(proc);
        return new TargetProcessAttestation(
            proc.Id,
            ParentPid: null,
            creation,
            image,
            sha,
            TryReadPeTimestamp(image),
            arch,
            cmdline,
            SessionId: null,
            modules);
    }

    public static TargetGenerationDto BeginGeneration(
        string projectName,
        string runId,
        Process proc,
        string? executablePath,
        string crashesDir,
        string? preferredDumpPath = null)
    {
        var attestation = CaptureAttestation(proc, executablePath);
        var generationId = Guid.NewGuid();
        var reservationId = Guid.NewGuid();
        var armedPath = preferredDumpPath
                        ?? Path.Combine(crashesDir, "dumps",
                            $"scream_{proc.Id}_{DateTime.UtcNow:yyyyMMdd_HHmmssfff}.dmp");

        var reservation = new DumpReservationDto(
            reservationId,
            generationId,
            projectName,
            proc.Id,
            attestation.CreationTimeUtc,
            attestation.ImagePath,
            attestation.ImageSha256,
            armedPath,
            DumpReservationState.Armed,
            DateTimeOffset.UtcNow);

        WriteReservation(crashesDir, reservation);

        return new TargetGenerationDto(
            generationId,
            projectName,
            runId,
            proc.Id,
            attestation.CreationTimeUtc,
            attestation.ImagePath,
            attestation.ImageSha256,
            attestation,
            reservationId,
            DateTimeOffset.UtcNow);
    }

    public static DumpReservationDto? TryReadReservation(string crashesDir, Guid reservationId) =>
        ResearchSidecarIO.TryRead<DumpReservationDto>(ReservationPath(crashesDir, reservationId), JsonOpts);

    public static void MarkTriggered(string crashesDir, Guid reservationId)
    {
        MutateReservation(crashesDir, reservationId, r =>
        {
            if (r.State is DumpReservationState.Expired or DumpReservationState.Rejected or DumpReservationState.Claimed)
                return r;
            return r with
            {
                State = DumpReservationState.Triggered,
                TriggeredAtUtc = DateTimeOffset.UtcNow,
            };
        });
    }

    public static void ExpireIfUnclaimed(string crashesDir, Guid reservationId, string reason = "target restarted")
    {
        MutateReservation(crashesDir, reservationId, r =>
        {
            if (r.State is DumpReservationState.Claimed or DumpReservationState.Validated
                or DumpReservationState.Rejected or DumpReservationState.Expired)
                return r;
            return r with
            {
                State = DumpReservationState.Expired,
                RejectReason = reason,
            };
        });
    }

    public static void UpdateArmedDumpPath(string crashesDir, Guid reservationId, string dumpPath)
    {
        MutateReservation(crashesDir, reservationId, r =>
            r.State is DumpReservationState.Claimed or DumpReservationState.Expired or DumpReservationState.Rejected
                ? r
                : r with { ArmedDumpPath = dumpPath });
    }

    public static void MarkDumpMaterialized(string crashesDir, Guid reservationId, string dumpPath)
    {
        MutateReservation(crashesDir, reservationId, r =>
        {
            if (r.State is DumpReservationState.Expired or DumpReservationState.Rejected or DumpReservationState.Claimed)
                return r;
            return r with
            {
                State = DumpReservationState.DumpMaterialized,
                MaterializedAtUtc = DateTimeOffset.UtcNow,
                MaterializedDumpPath = dumpPath,
            };
        });
    }

    /// <summary>
    /// Claim a materialized dump exactly once for a crash. Returns null + reject reason on CAS failure.
    /// </summary>
    public static (DumpReservationDto? Reservation, string? Error) TryClaimOnce(
        string crashesDir,
        Guid reservationId,
        Guid crashId,
        long iterationId)
    {
        var path = ReservationPath(crashesDir, reservationId);
        var gate = ReservationLocks.GetOrAdd(Path.GetFullPath(path), static _ => new object());
        lock (gate)
        {
            var current = ResearchSidecarIO.TryRead<DumpReservationDto>(path, JsonOpts);
            if (current is null)
                return (null, "dump reservation missing");

            if (current.State == DumpReservationState.Claimed)
            {
                if (current.ClaimedCrashId == crashId)
                    return (current, null);
                return (null,
                    $"dump reservation already claimed by crash {current.ClaimedCrashId} (iteration {current.ClaimedIterationId})");
            }

            if (current.State is DumpReservationState.Expired or DumpReservationState.Rejected)
                return (null, $"dump reservation state={current.State}");

            if (current.State is not (DumpReservationState.DumpMaterialized or DumpReservationState.Triggered or DumpReservationState.Armed))
                return (null, $"dump reservation not claimable (state={current.State})");

            // Allow claim from Armed/Triggered when dump path already usable (race with materialize).
            if (current.State == DumpReservationState.Armed
                && string.IsNullOrWhiteSpace(current.MaterializedDumpPath)
                && (string.IsNullOrWhiteSpace(current.ArmedDumpPath) || !CrashDumpPaths.IsUsableDump(current.ArmedDumpPath)))
            {
                return (null, "dump reservation armed but dump not materialized");
            }

            var claimed = current with
            {
                State = DumpReservationState.Claimed,
                ClaimedAtUtc = DateTimeOffset.UtcNow,
                ClaimedCrashId = crashId,
                ClaimedIterationId = iterationId,
                MaterializedDumpPath = FirstNonEmpty(
                    current.MaterializedDumpPath,
                    CrashDumpPaths.IsUsableDump(current.ArmedDumpPath) ? current.ArmedDumpPath : null),
            };
            AtomicFile.WriteAllText(path, JsonSerializer.Serialize(claimed, JsonOpts));
            return (claimed, null);
        }
    }

    public static CrashArtifactIdentity BuildIdentity(
        Guid crashId,
        string runId,
        TargetGenerationDto generation,
        long iterationId,
        string projectName,
        string inputSha256,
        string inputPath,
        string? dumpPath,
        DateTimeOffset? sendStartedUtc,
        DateTimeOffset? sendCompletedUtc,
        DateTimeOffset? failureObservedUtc,
        DumpReservationDto? reservation = null)
    {
        var dumpPid = TryParseDumpPid(dumpPath);
        DateTimeOffset? dumpCreated = null;
        if (!string.IsNullOrWhiteSpace(dumpPath) && File.Exists(dumpPath))
        {
            try { dumpCreated = new DateTimeOffset(File.GetCreationTimeUtc(dumpPath)); }
            catch { /* ignore */ }
        }

        var engine = RandallBuildInfo.Current;
        return new CrashArtifactIdentity(
            crashId,
            runId,
            generation.TargetGenerationId,
            iterationId,
            projectName,
            inputSha256,
            inputPath,
            generation.ExecutablePath,
            generation.ExecutableSha256,
            generation.Pid,
            generation.ProcessStartTimeUtc,
            sendStartedUtc,
            sendCompletedUtc,
            failureObservedUtc,
            dumpCreated,
            dumpPath,
            dumpPid,
            DumpProcessName: null,
            DumpProcessStartTimeUtc: generation.ProcessStartTimeUtc,
            engine.Version,
            engine.GitCommit ?? "",
            reservation?.ReservationId ?? generation.DumpReservationId,
            ArtifactIntegrityStatus.Unverified,
            SecondaryExceptionKind.None,
            generation.Attestation,
            DumpAttestation: null);
    }

    public static ArtifactValidationResult ValidateIdentity(
        CrashArtifactIdentity identity,
        DumpReservationDto? reservation = null,
        string? expectedInputSha256 = null,
        DebuggerObservation? debugger = null,
        bool expectNativeTarget = true)
    {
        var hard = new List<string>();
        var warnings = new List<string>();

        if (identity.CrashId == Guid.Empty)
            hard.Add("CrashId is empty");
        if (identity.TargetGenerationId == Guid.Empty)
            hard.Add("TargetGenerationId is empty");
        if (string.IsNullOrWhiteSpace(identity.RunId))
            warnings.Add("RunId empty on identity envelope");

        if (reservation is not null)
        {
            if (reservation.TargetGenerationId != identity.TargetGenerationId)
                hard.Add("Dump reservation TargetGenerationId mismatch");
            if (reservation.ExpectedPid != identity.ExpectedPid)
                hard.Add($"Dump reservation PID {reservation.ExpectedPid} ≠ expected {identity.ExpectedPid}");
            if (reservation.State == DumpReservationState.Claimed
                && reservation.ClaimedCrashId is Guid claimed
                && claimed != identity.CrashId)
            {
                hard.Add($"Dump reservation claimed by different crash {claimed}");
            }

            if (reservation.State is DumpReservationState.Rejected or DumpReservationState.Expired)
                hard.Add($"Dump reservation state={reservation.State}");
        }

        if (identity.DumpPid is int dumpPid && dumpPid != identity.ExpectedPid)
            hard.Add($"Dump PID {dumpPid} ≠ expected target PID {identity.ExpectedPid}");

        if (!string.IsNullOrWhiteSpace(identity.DumpPath) && File.Exists(identity.DumpPath))
        {
            if (identity.DumpCreatedUtc is DateTimeOffset created)
            {
                if (created < identity.ProcessStartTimeUtc.AddSeconds(-2))
                    hard.Add("Dump creation time precedes target process start");
                if (identity.SendStartedUtc is DateTimeOffset sendStart
                    && created < sendStart.AddSeconds(-5))
                    hard.Add("Dump creation time precedes send-start (stale dump)");
            }
        }
        else if (!string.IsNullOrWhiteSpace(identity.DumpPath))
        {
            warnings.Add("Dump path recorded but file missing");
        }

        if (!string.IsNullOrWhiteSpace(expectedInputSha256)
            && !string.IsNullOrWhiteSpace(identity.InputSha256)
            && !string.Equals(expectedInputSha256, identity.InputSha256, StringComparison.OrdinalIgnoreCase))
        {
            hard.Add("Input SHA-256 mismatch vs crash payload");
        }

        if (!string.IsNullOrWhiteSpace(identity.InputPath) && File.Exists(identity.InputPath))
        {
            var onDisk = FileSha256(identity.InputPath);
            if (!string.IsNullOrWhiteSpace(identity.InputSha256)
                && !string.IsNullOrWhiteSpace(onDisk)
                && !string.Equals(onDisk, identity.InputSha256, StringComparison.OrdinalIgnoreCase)
                && !LooksLikeShortHash(identity.InputSha256))
            {
                // CrashStore uses content hash that may not be full SHA-256 — warn only for full digests.
                if (identity.InputSha256.Length >= 64)
                    hard.Add("Input file SHA-256 does not match identity envelope");
            }
        }

        if (string.IsNullOrWhiteSpace(identity.ExecutableSha256))
            warnings.Add("Executable SHA-256 unavailable");

        var secondary = ClassifySecondaryException(debugger);
        if (secondary != SecondaryExceptionKind.None)
            warnings.Add($"Fault classified as {secondary} — stronger promotion blocked without primary fault");

        if (expectNativeTarget && debugger is not null)
        {
            foreach (var mod in UnexpectedManagedModules(debugger, identity.TargetAttestation))
            {
                warnings.Add(
                    $"Unexpected managed runtime module '{mod}' on native target — attribution requires review");
            }
        }

        // Incomplete envelope (no generation) → Unverified, not Rejected (legacy crashes).
        ArtifactIntegrityStatus status;
        if (hard.Count > 0)
            status = ArtifactIntegrityStatus.Rejected;
        else if (identity.TargetGenerationId == Guid.Empty)
            status = ArtifactIntegrityStatus.Unverified;
        else if (warnings.Count > 0)
            status = ArtifactIntegrityStatus.VerifiedWithWarnings;
        else
            status = ArtifactIntegrityStatus.Verified;

        var stamped = identity with
        {
            IntegrityStatus = status,
            SecondaryException = secondary,
        };

        var summary = status switch
        {
            ArtifactIntegrityStatus.Verified => "Identity verified",
            ArtifactIntegrityStatus.VerifiedWithWarnings =>
                $"Verified with warnings: {string.Join("; ", warnings.Take(3))}",
            ArtifactIntegrityStatus.Rejected =>
                $"Rejected: {string.Join("; ", hard.Take(3))}",
            _ => "Unverified — incomplete identity envelope",
        };

        return new ArtifactValidationResult(
            status,
            stamped,
            hard,
            warnings,
            reservation?.State,
            secondary,
            summary);
    }

    /// <summary>
    /// Strong research promotion (root-cause / primitives / twins / genealogy / Court Confirmed)
    /// requires non-Rejected identity and a primary (non-teardown-only) fault.
    /// </summary>
    public static bool AllowsStrongPromotion(ArtifactValidationResult? validation, out string? reason)
    {
        // Legacy crashes without an identity envelope remain analyzable (Unverified).
        // Rejected / teardown-only dumps must not promote.
        if (validation is null)
        {
            reason = null;
            return true;
        }

        if (validation.Status == ArtifactIntegrityStatus.Rejected)
        {
            reason = validation.Summary ?? "Artifact identity Rejected";
            return false;
        }

        if (validation.SecondaryException is SecondaryExceptionKind.Teardown
            or SecondaryExceptionKind.SecondaryException)
        {
            reason =
                $"Secondary/teardown fault ({validation.SecondaryException}) — block family/root-cause/primitive/twin promotion without primary fault";
            return false;
        }

        reason = null;
        return true;
    }

    /// <summary>Court Confirmed / R5+ requires Verified identity when an envelope exists.</summary>
    public static bool AllowsCourtConfirmation(ArtifactValidationResult? validation, out string? reason)
    {
        if (validation is null)
        {
            // Legacy crashes without an identity envelope — Court still uses Skeptic+facts only.
            reason = null;
            return true;
        }

        if (!AllowsStrongPromotion(validation, out reason))
            return false;

        if (validation.Status is ArtifactIntegrityStatus.Unverified or ArtifactIntegrityStatus.Rejected)
        {
            reason = "Court confirmation requires Verified identity chain";
            return false;
        }

        reason = null;
        return true;
    }

    public static SecondaryExceptionKind ClassifySecondaryException(DebuggerObservation? debugger)
    {
        if (debugger is null)
            return SecondaryExceptionKind.None;

        if (ScreamInvestigator.IsTeardownExitPath(debugger.FaultingFunction, debugger.FaultingModule))
            return SecondaryExceptionKind.Teardown;

        var fn = debugger.FaultingFunction ?? "";
        var mod = debugger.FaultingModule ?? "";
        if (fn.Contains("NtTerminateProcess", StringComparison.OrdinalIgnoreCase)
            || fn.Contains("ZwTerminateProcess", StringComparison.OrdinalIgnoreCase)
            || (mod.Contains("ntdll", StringComparison.OrdinalIgnoreCase)
                && fn.Contains("TerminateProcess", StringComparison.OrdinalIgnoreCase)))
        {
            return SecondaryExceptionKind.Teardown;
        }

        // Classic secondary: write AV @ 0 on ntdll terminate/exit with no primary controlled site.
        if (debugger.Access == DebuggerAccessKind.Write
            && IsNullOrNearNull(debugger.FaultAddress)
            && (mod.Contains("ntdll", StringComparison.OrdinalIgnoreCase)
                || ScreamInvestigator.IsTeardownExitPath(fn, mod)))
        {
            return SecondaryExceptionKind.SecondaryException;
        }

        return SecondaryExceptionKind.None;
    }

    public static IReadOnlyList<string> UnexpectedManagedModules(
        DebuggerObservation debugger,
        TargetProcessAttestation? attestation)
    {
        var unexpected = new List<string>();
        var image = Path.GetFileNameWithoutExtension(attestation?.ImagePath ?? "") ?? "";
        var looksNative = !string.IsNullOrWhiteSpace(image)
                          && !image.Contains("dotnet", StringComparison.OrdinalIgnoreCase)
                          && !ManagedRuntimeModules.Contains(image);

        if (!looksNative && string.IsNullOrWhiteSpace(attestation?.ImagePath))
        {
            // Unknown target class — still flag clrjit when faulting module is managed and name looks native from dump alone.
            looksNative = true;
        }

        if (!looksNative)
            return unexpected;

        void Consider(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return;
            var leaf = Path.GetFileNameWithoutExtension(name.Trim());
            if (ManagedRuntimeModules.Contains(leaf) || ManagedRuntimeModules.Contains(name.Trim()))
            {
                if (!unexpected.Contains(leaf, StringComparer.OrdinalIgnoreCase))
                    unexpected.Add(leaf);
            }
        }

        Consider(debugger.FaultingModule);
        foreach (var frame in debugger.Stack ?? [])
            Consider(frame.Module);

        if (!string.IsNullOrWhiteSpace(debugger.ModulesText))
        {
            foreach (var line in debugger.ModulesText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                foreach (var mod in ManagedRuntimeModules)
                {
                    if (line.Contains(mod, StringComparison.OrdinalIgnoreCase))
                        Consider(mod);
                }
            }
        }

        return unexpected;
    }

    public static void PersistIdentity(string crashesDir, CrashArtifactIdentity identity)
    {
        Directory.CreateDirectory(crashesDir);
        AtomicFile.WriteAllText(
            IdentityPath(crashesDir, identity.CrashId),
            JsonSerializer.Serialize(identity, JsonOpts));
    }

    public static CrashArtifactIdentity? TryReadIdentity(string crashesDir, Guid crashId) =>
        ResearchSidecarIO.TryRead<CrashArtifactIdentity>(IdentityPath(crashesDir, crashId), JsonOpts);

    public static ArtifactValidationResult? ResolveForCrash(
        string crashesDir,
        Guid crashId,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        string? dumpPath = null)
    {
        if (sidecar?.ArtifactIdentity is { } id)
            return ValidateIdentity(id, debugger: debugger);

        var fromDisk = TryValidateFromDisk(crashesDir, crashId, debugger);
        if (fromDisk is not null)
            return fromDisk;

        var secondary = ClassifySecondaryException(debugger);
        if (secondary == SecondaryExceptionKind.None)
            return null;

        var stub = new CrashArtifactIdentity(
            crashId,
            sidecar?.RunId ?? "",
            Guid.Empty,
            sidecar?.Iteration ?? 0,
            sidecar?.Project ?? "?",
            sidecar?.InputHash ?? "",
            sidecar?.InputPath ?? "",
            "",
            "",
            0,
            DateTimeOffset.UnixEpoch,
            null,
            null,
            null,
            null,
            dumpPath ?? sidecar?.MiniDumpPath,
            null,
            null,
            null,
            RandallBuildInfo.Current.Version,
            RandallBuildInfo.Current.GitCommit ?? "",
            IntegrityStatus: ArtifactIntegrityStatus.Unverified,
            SecondaryException: secondary);

        return new ArtifactValidationResult(
            ArtifactIntegrityStatus.Unverified,
            stub,
            [],
            [$"Fault classified as {secondary}"],
            SecondaryException: secondary,
            Summary: "Teardown/secondary fault without verified identity");
    }

    public static ArtifactValidationResult? TryValidateFromDisk(
        string crashesDir,
        Guid crashId,
        DebuggerObservation? debugger = null)
    {
        var identity = TryReadIdentity(crashesDir, crashId);
        if (identity is null)
            return null;

        DumpReservationDto? reservation = null;
        if (identity.DumpReservationId is Guid rid)
            reservation = TryReadReservation(crashesDir, rid);

        return ValidateIdentity(identity, reservation, identity.InputSha256, debugger);
    }

    public static int? TryParseDumpPid(string? dumpPath)
    {
        if (string.IsNullOrWhiteSpace(dumpPath))
            return null;
        var name = Path.GetFileName(dumpPath);
        var m = DumpPidRegex.Match(name);
        if (m.Success && int.TryParse(m.Groups[1].Value, out var pid))
            return pid;
        return null;
    }

    private static void WriteReservation(string crashesDir, DumpReservationDto reservation)
    {
        var path = ReservationPath(crashesDir, reservation.ReservationId);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(reservation, JsonOpts));
    }

    private static void MutateReservation(
        string crashesDir,
        Guid reservationId,
        Func<DumpReservationDto, DumpReservationDto> mutate)
    {
        var path = ReservationPath(crashesDir, reservationId);
        var gate = ReservationLocks.GetOrAdd(Path.GetFullPath(path), static _ => new object());
        lock (gate)
        {
            var current = ResearchSidecarIO.TryRead<DumpReservationDto>(path, JsonOpts);
            if (current is null)
                return;
            var next = mutate(current);
            AtomicFile.WriteAllText(path, JsonSerializer.Serialize(next, JsonOpts));
        }
    }

    private static IReadOnlyList<string> CaptureModuleBaseline(Process proc)
    {
        try
        {
            proc.Refresh();
            return proc.Modules
                .Cast<ProcessModule>()
                .Select(m => Path.GetFileNameWithoutExtension(m.ModuleName) ?? m.ModuleName)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(64)
                .ToList()!;
        }
        catch
        {
            return [];
        }
    }

    private static string? TryMainModulePath(Process proc)
    {
        try { return proc.MainModule?.FileName; }
        catch { return null; }
    }

    private static bool IsWow64(Process proc)
    {
        try
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;
            // Heuristic: 32-bit process on 64-bit OS often lacks full MainModule access differently.
            _ = proc.MainModule;
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static uint? TryReadPeTimestamp(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            using var fs = File.OpenRead(path);
            if (fs.Length < 0x40)
                return null;
            Span<byte> dos = stackalloc byte[0x40];
            if (fs.Read(dos) < 0x40)
                return null;
            if (dos[0] != (byte)'M' || dos[1] != (byte)'Z')
                return null;
            var e_lfanew = BitConverter.ToInt32(dos.Slice(0x3C));
            if (e_lfanew <= 0 || e_lfanew > fs.Length - 8)
                return null;
            fs.Seek(e_lfanew, SeekOrigin.Begin);
            Span<byte> pe = stackalloc byte[8];
            if (fs.Read(pe) < 8)
                return null;
            if (pe[0] != (byte)'P' || pe[1] != (byte)'E')
                return null;
            // COFF TimeDateStamp is at PE+8.
            fs.Seek(e_lfanew + 8, SeekOrigin.Begin);
            Span<byte> ts = stackalloc byte[4];
            if (fs.Read(ts) < 4)
                return null;
            return BitConverter.ToUInt32(ts);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsNullOrNearNull(string? addr)
    {
        if (string.IsNullOrWhiteSpace(addr))
            return false;
        var cls = ScreamInvestigator.ClassifyAddress(addr);
        return cls is DebuggerAddressClass.NullPage or DebuggerAddressClass.NearNull;
    }

    private static bool LooksLikeShortHash(string hash) =>
        hash.Length is > 0 and < 40;

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v;
        }
        return null;
    }

    private static string? Truncate(string? s, int max) =>
        string.IsNullOrEmpty(s) ? s : s.Length <= max ? s : s[..max];
}
