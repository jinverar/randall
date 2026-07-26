using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class EvidenceFactBuilderTests
{
    [Fact]
    public void FromDebuggerProvenance_MapsObservedAndInferredKinds()
    {
        var obs = new DebuggerObservation(
            Ok: true,
            DumpPath: "dump.dmp",
            ObservationPath: "obs.json",
            ExceptionCode: "c0000005",
            ExceptionHint: "AV",
            Access: DebuggerAccessKind.Read,
            FaultAddress: "0x41414141",
            FaultAddressClass: DebuggerAddressClass.AsciiPattern,
            Rip: "0x401000",
            FaultingModule: "vuln.exe",
            FaultingFunction: "parse",
            FunctionOffset: "+0x42",
            Stack: [],
            StackHash: "abc",
            RegistersText: null,
            DisasmNearRip: null,
            MemoryNearRsp: null,
            ModulesText: null,
            HeapProbeText: null,
            AddressQueryText: null,
            ExrText: null,
            ExploitableClassification: "EXPLOITABLE",
            ExploitableDescription: null,
            HeapSignal: null,
            SuspectedInputInfluence: "HIGH",
            ExploitabilityHint: "HIGH",
            Confidence: 0.9,
            Diagnosis: "Read AV at ASCII pattern",
            DebuggerScreamBonus: 20,
            AnalyzeTimedOut: false,
            Error: null,
            At: DateTimeOffset.UtcNow,
            RegisterMatches: [new RegisterPayloadMatchDto("RAX", "41414141", 128, 4, "ascii", "pattern")],
            PrimaryRegisterMatch: "RAX",
            Provenance: new DebuggerObservationProvenance(
                ExceptionCode: new DebuggerFactDto<string>("c0000005", "!analyze -v", DebuggerFactConfidence.Medium, DebuggerFactKind.Observed),
                FaultAddress: new DebuggerFactDto<string>("0x41414141", ".exr -1", DebuggerFactConfidence.High, DebuggerFactKind.Observed),
                FaultAddressClass: new DebuggerFactDto<DebuggerAddressClass>(
                    DebuggerAddressClass.AsciiPattern, "!address / heuristics", DebuggerFactConfidence.Medium, DebuggerFactKind.Inferred)));

        var facts = EvidenceFactBuilder.FromDebuggerProvenance(obs, DateTimeOffset.UtcNow).ToList();

        Assert.Contains(facts, f => f.Name == "faultAddress" && f.ObservationType == EvidenceObservationType.Observed);
        Assert.Contains(facts, f => f.Name == "faultAddressClass" && f.ObservationType == EvidenceObservationType.Inferred);
        Assert.Contains(facts, f => f.Name == "debugger.inputInfluence" && f.Value == "HIGH");
        Assert.Contains(facts, f => f.Name == "debugger.register.RAX");
    }

    [Fact]
    public void Build_AggregatesCorruptionChainAndOracle()
    {
        var crashId = Guid.NewGuid();
        var chain = new CrashCorruptionChainDto(
            true, crashId, "demo", "HIGH", "Input pattern reaches fault PC",
            null, "expand", 128, "dword at +128", ["seed", "expand"], [],
            null, null, DateTimeOffset.UtcNow);

        var oracle = new OracleScore(72, [new OracleScoreTerm("crash", 60, "AV")], "+60 crash");

        var dto = EvidenceFactBuilder.Build(
            crashId, "demo", oracleScore: oracle, corruptionChain: chain);

        Assert.True(dto.Ok);
        Assert.Contains(dto.Facts, f => f.Source == "corruption_chain" && f.Name == "corruption.confidence");
        Assert.Contains(dto.Facts, f => f.Source == "oracle" && f.Name == "oracle.score");
    }

    [Fact]
    public void PersistForCrash_RoundTripsJson()
    {
        var crashId = Guid.NewGuid();
        var dir = Path.Combine(Path.GetTempPath(), "randall-evidence-" + crashId.ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var triage = new CrashTriageDto(
                "access_violation", "high", "test", true, false, "key",
                "AV", "0xDEAD", null, null, null, 64, "pattern");

            EvidenceFactBuilder.PersistForCrash(dir, crashId, "demo", triage: triage);

            var path = EvidenceFactBuilder.PathFor(dir, crashId);
            Assert.True(File.Exists(path));

            var loaded = EvidenceFactBuilder.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(crashId, loaded!.CrashId);
            Assert.Contains(loaded.Facts, f => f.Name == "triage.ipControlled");
            Assert.Contains(loaded.Facts, f => f.ObservationType == EvidenceObservationType.Observed);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void FromHypotheses_MapsStatusToObservationType()
    {
        var crashId = Guid.NewGuid();
        var set = new HypothesisSetDto(
            true,
            crashId,
            "demo",
            [
                new HypothesisDto(
                    "H1",
                    crashId,
                    "Pattern depth controls RIP",
                    65,
                    new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "Sweep ±4", OffsetBytes: 128),
                    "Crash persists",
                    HypothesisStatus.Confirmed,
                    Evidence: ["corruption:HIGH"]),
            ],
            DateTimeOffset.UtcNow);

        var facts = EvidenceFactBuilder.FromHypotheses(set, DateTimeOffset.UtcNow).ToList();

        Assert.Contains(facts, f => f.Name == "hypothesis.H1" && f.ObservationType == EvidenceObservationType.ExperimentallyConfirmed);
        Assert.Contains(facts, f => f.Name.StartsWith("hypothesis.H1.evidence."));
    }
}
