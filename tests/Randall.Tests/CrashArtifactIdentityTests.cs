using System.Diagnostics;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CrashArtifactIdentityTests
{
    [Fact]
    public void ValidateIdentity_rejects_dump_pid_mismatch()
    {
        var gen = Guid.NewGuid();
        var crashId = Guid.NewGuid();
        var identity = new CrashArtifactIdentity(
            crashId, "run-1", gen, 7, "vulnserver",
            "a".PadLeft(64, 'a'), "in.bin", @"C:\targets\vulnserver.exe", "b".PadLeft(64, 'b'),
            ExpectedPid: 11860,
            ProcessStartTimeUtc: DateTimeOffset.UtcNow.AddMinutes(-1),
            SendStartedUtc: DateTimeOffset.UtcNow.AddSeconds(-5),
            SendCompletedUtc: DateTimeOffset.UtcNow.AddSeconds(-4),
            FailureObservedUtc: DateTimeOffset.UtcNow,
            DumpCreatedUtc: DateTimeOffset.UtcNow,
            DumpPath: @"dumps\scream_99999_20260729_020634114.dmp",
            DumpPid: 99999,
            DumpProcessName: null,
            DumpProcessStartTimeUtc: DateTimeOffset.UtcNow.AddMinutes(-1),
            AnalysisEngineVersion: "test",
            AnalysisEngineCommit: "deadbeef");

        var result = CrashArtifactIdentityService.ValidateIdentity(identity);
        Assert.Equal(ArtifactIntegrityStatus.Rejected, result.Status);
        Assert.Contains(result.HardFailures, f => f.Contains("Dump PID", StringComparison.OrdinalIgnoreCase));
        Assert.False(CrashArtifactIdentityService.AllowsStrongPromotion(result, out var reason));
        Assert.Contains("Rejected", reason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateIdentity_verified_with_managed_module_warning()
    {
        var gen = Guid.NewGuid();
        var crashId = Guid.NewGuid();
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var identity = new CrashArtifactIdentity(
            crashId, "run-1", gen, 3, "vulnserver",
            "c".PadLeft(64, 'c'), "in.bin", @"C:\targets\vulnserver.exe", "d".PadLeft(64, 'd'),
            4242, start,
            start.AddSeconds(10), start.AddSeconds(11), start.AddSeconds(12), start.AddSeconds(12),
            @"dumps\scream_4242_20260729_020634114.dmp", 4242, "vulnserver", start,
            "test", "abc",
            TargetAttestation: new TargetProcessAttestation(
                4242, null, start, @"C:\targets\vulnserver.exe", "d".PadLeft(64, 'd'),
                null, "x64", null, null, ["vulnserver", "ntdll"]));

        var debugger = MakeObs(
            faultModule: "clrjit",
            faultFunction: "Compiler",
            faultAddress: "0x41414141",
            access: DebuggerAccessKind.Write,
            addressClass: DebuggerAddressClass.AsciiPattern,
            modulesText: "clrjit coreclr",
            stack: [new DebuggerStackFrameDto(0, "0x1", "clrjit", "Compiler", "+0x10")]);

        var result = CrashArtifactIdentityService.ValidateIdentity(identity, debugger: debugger);
        Assert.Equal(ArtifactIntegrityStatus.VerifiedWithWarnings, result.Status);
        Assert.Contains(result.Warnings, w => w.Contains("Unexpected managed runtime module", StringComparison.OrdinalIgnoreCase));
        Assert.True(CrashArtifactIdentityService.AllowsStrongPromotion(result, out _));
    }

    [Fact]
    public void Dump_reservation_claim_once()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-id-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(dir, "dumps"));
        try
        {
            var dumpPath = Path.Combine(dir, "dumps", "scream_100_test.dmp");
            File.WriteAllBytes(dumpPath, [1, 2, 3, 4]);

            using var self = Process.GetCurrentProcess();
            var exe = Environment.ProcessPath ?? "dotnet";
            var gen = CrashArtifactIdentityService.BeginGeneration(
                "lab", "run", self, exe, dir, dumpPath);
            Assert.NotNull(gen.DumpReservationId);
            var rid = gen.DumpReservationId!.Value;
            CrashArtifactIdentityService.MarkDumpMaterialized(dir, rid, dumpPath);

            var crashA = Guid.NewGuid();
            var crashB = Guid.NewGuid();
            var (first, err1) = CrashArtifactIdentityService.TryClaimOnce(dir, rid, crashA, 1);
            Assert.Null(err1);
            Assert.NotNull(first);
            Assert.Equal(DumpReservationState.Claimed, first!.State);
            Assert.Equal(crashA, first.ClaimedCrashId);

            var (second, err2) = CrashArtifactIdentityService.TryClaimOnce(dir, rid, crashB, 2);
            Assert.Null(second);
            Assert.Contains("already claimed", err2 ?? "", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Teardown_NtTerminateProcess_blocks_strong_promotion()
    {
        var debugger = MakeObs(
            faultModule: "ntdll",
            faultFunction: "NtTerminateProcess",
            faultAddress: "0x0",
            access: DebuggerAccessKind.Write,
            addressClass: DebuggerAddressClass.NullPage,
            functionOffset: "+0x14");

        Assert.Equal(SecondaryExceptionKind.Teardown,
            CrashArtifactIdentityService.ClassifySecondaryException(debugger));

        var validation = CrashArtifactIdentityService.ResolveForCrash(
            Path.GetTempPath(), Guid.NewGuid(), null, debugger);
        Assert.NotNull(validation);
        Assert.False(CrashArtifactIdentityService.AllowsStrongPromotion(validation, out var reason));
        Assert.Contains("teardown", reason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejected_blocks_court_confirmation()
    {
        var identity = new CrashArtifactIdentity(
            Guid.NewGuid(), "run", Guid.NewGuid(), 1, "p",
            "a".PadLeft(64, 'a'), "i.bin", "e.exe", "b".PadLeft(64, 'b'),
            1, DateTimeOffset.UtcNow, null, null, null, null,
            @"scream_2_x.dmp", 2, null, null, "v", "c");
        var validation = CrashArtifactIdentityService.ValidateIdentity(identity);
        Assert.Equal(ArtifactIntegrityStatus.Rejected, validation.Status);
        Assert.False(CrashArtifactIdentityService.AllowsCourtConfirmation(validation, out _));
        Assert.False(EvidenceCourt.PassesPromotionGate(null, [], artifactValidation: validation));
    }

    [Fact]
    public void Evidence_honesty_demotes_interpretive_observed_atoms()
    {
        var at = DateTimeOffset.UtcNow;
        var facts = new[]
        {
            EvidenceFactBuilder.Fact(
                "corruption.summary", "mutation introduced value", "corruption_chain", null,
                EvidenceObservationType.Observed, 0.9, at),
            EvidenceFactBuilder.Fact(
                "backwardTrace.story", "story", "backward_trace", null,
                EvidenceObservationType.Observed, 0.9, at),
            EvidenceFactBuilder.Fact(
                "debugger.inputInfluence", "HIGH", "debugger", null,
                EvidenceObservationType.Observed, 0.9, at),
            EvidenceFactBuilder.Fact(
                "faultAddress", "0x41414141", "debugger", null,
                EvidenceObservationType.Observed, 0.9, at),
        };

        var normalized = EvidenceFactBuilder.EnforceObservationHonesty(facts);
        Assert.Equal(EvidenceObservationType.Inferred, normalized.First(f => f.Name == "corruption.summary").ObservationType);
        Assert.Equal(EvidenceObservationType.Inferred, normalized.First(f => f.Name == "backwardTrace.story").ObservationType);
        Assert.Equal(EvidenceObservationType.Inferred, normalized.First(f => f.Name == "debugger.inputInfluence").ObservationType);
        Assert.Equal(EvidenceObservationType.Observed, normalized.First(f => f.Name == "faultAddress").ObservationType);

        Assert.Equal(EvidenceKind.Derived, EvidenceLedger.KindFor(normalized.First(f => f.Name == "corruption.summary")));
        Assert.Equal(EvidenceKind.Observed, EvidenceLedger.KindFor(normalized.First(f => f.Name == "faultAddress")));
    }

    [Fact]
    public void Coverage_labels_split_bb_from_corpus_novelty()
    {
        var method = typeof(StalkDashboard).GetMethod(
            "BuildCoverageSummary",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        var result = ((double Percent, string Label, string Detail))method!.Invoke(
            null, [0, 3, 4, "Live (corpus-novelty)", false])!;
        Assert.Equal("Corpus novelty", result.Label);
        Assert.DoesNotContain("Basic-block", result.Label, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not BB", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryParseDumpPid_from_scream_name()
    {
        Assert.Equal(11860, CrashArtifactIdentityService.TryParseDumpPid(
            @"data\crashes\x\dumps\scream_11860_20260729_020634114.dmp"));
        Assert.Null(CrashArtifactIdentityService.TryParseDumpPid("random.dmp"));
    }

    private static DebuggerObservation MakeObs(
        string faultModule,
        string faultFunction,
        string faultAddress,
        DebuggerAccessKind access,
        DebuggerAddressClass addressClass,
        string? modulesText = null,
        string? functionOffset = "+0x10",
        IReadOnlyList<DebuggerStackFrameDto>? stack = null) =>
        new(
            Ok: true,
            DumpPath: "x.dmp",
            ObservationPath: null,
            ExceptionCode: "c0000005",
            ExceptionHint: "ACCESS_VIOLATION",
            Access: access,
            FaultAddress: faultAddress,
            FaultAddressClass: addressClass,
            Rip: "0x7ffe0000",
            FaultingModule: faultModule,
            FaultingFunction: faultFunction,
            FunctionOffset: functionOffset,
            Stack: stack ?? [],
            StackHash: "h",
            RegistersText: null,
            DisasmNearRip: null,
            MemoryNearRsp: null,
            ModulesText: modulesText,
            HeapProbeText: null,
            AddressQueryText: null,
            ExrText: null,
            ExploitableClassification: null,
            ExploitableDescription: null,
            HeapSignal: null,
            SuspectedInputInfluence: "LOW",
            ExploitabilityHint: "UNKNOWN",
            Confidence: 0.4,
            Diagnosis: "test",
            DebuggerScreamBonus: 0,
            AnalyzeTimedOut: false,
            Error: null,
            At: DateTimeOffset.UtcNow);
}
