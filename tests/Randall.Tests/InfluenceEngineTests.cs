using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class InfluenceEngineTests
{
    [Fact]
    public void Build_maps_register_match_to_observed_link()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(20), 0x41414141u);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rax=0000000041414141\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!memcpy+0x12");

        var chain = CorruptionChainBuilder.Build(id, "lab", null, obs, null, payload);
        var map = InfluenceEngine.Build(id, "lab", null, null, obs, chain, payload: payload);

        Assert.True(map.Ok);
        Assert.Contains(map.Links, l =>
            l.Status == InfluenceConfirmationStatus.Observed
            && l.Region.StartOffset == 20
            && l.State.Kind == InfluencedStateKind.Register
            && l.State.Label == "RAX");
        Assert.Contains(map.Facts, f => f.Source == "input_attribution" || f.Name.StartsWith("influence.", StringComparison.Ordinal));
    }

    [Fact]
    public void Build_adds_length_copy_candidate_for_memcpy_expand()
    {
        var id = Guid.NewGuid();
        var payload = new byte[80];
        BitConverter.TryWriteBytes(payload.AsSpan(60), 0x42424242u);
        var lineage = new List<string> { "bitflip", "expand", "havoc" };

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 42424242\n",
            regs: "rdx=0000000042424242\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!memcpy+0x12");

        var sidecar = new CrashSidecarDto(
            id, "run-1", 1, "lab", "HELLO", "expand",
            lineage, null, "seed", [], "abc", "x.bin", payload.Length,
            -1073741819, "AV", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, obs, null, payload);
        var map = InfluenceEngine.Build(id, "lab", sidecar, null, obs, chain, payload: payload);

        Assert.Contains(map.Links, l =>
            l.Mechanism == "length→alloc/copy"
            && l.Status == InfluenceConfirmationStatus.Candidate
            && l.Honesty == InfluenceHonestyLabel.Hypothesized
            && l.State.Kind == InfluencedStateKind.CopyLength);
    }

    [Fact]
    public void Build_does_not_add_length_copy_for_boundary_only_null_write()
    {
        var id = Guid.NewGuid();
        var payload = new byte[32];
        var sidecar = new CrashSidecarDto(
            id, "run-1", 1, "lab", "TRUN", "boundary",
            ["boundary"], null, "seed", [], "abc", "x.bin", payload.Length,
            -1073741819, "AV", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 00000000\nParameter[0]: 00000001\n",
            regs: "rcx=0000000000000000\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!SafeExitProcess+0x12",
            sidecar: sidecar);

        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, obs, null, payload);
        var map = InfluenceEngine.Build(id, "lab", sidecar, null, obs, chain, payload: payload);

        Assert.DoesNotContain(map.Links, l =>
            l.Mechanism.Contains("length→alloc/copy", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ApplyHypothesisOutcomes_promotes_confirmed_offset_link()
    {
        var id = Guid.NewGuid();
        var links = new List<InfluenceLinkDto>
        {
            new(
                "inf-depth-14",
                new InfluenceRegionDto(20, 24, 4, "payload+20", "bitflip", 0),
                new InfluencedStateDto(InfluencedStateKind.FaultAddress, "fault", "0x41414141"),
                InfluenceConfirmationStatus.Candidate,
                "input→fault state",
                ["patternDepth:20"],
                HypothesisId: "hyp-offset-14"),
        };

        var hypotheses = new HypothesisSetDto(
            true,
            id,
            "lab",
            [
                new HypothesisDto(
                    "hyp-offset-14",
                    id,
                    "Offset 20 influences fault",
                    72,
                    new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep", "bitflip", 20),
                    "same fault",
                    HypothesisStatus.Confirmed,
                    new HypothesisResultDto(HypothesisStatus.Confirmed, 80, "crash reproduced", 5, DateTimeOffset.UtcNow, 72)),
            ],
            DateTimeOffset.UtcNow);

        InfluenceEngine.ApplyHypothesisOutcomes(links, hypotheses);

        Assert.Equal(InfluenceConfirmationStatus.Confirmed, links[0].Status);
    }

    [Fact]
    public void Persist_roundtrips_json()
    {
        var id = Guid.NewGuid();
        var dir = Path.Combine(Path.GetTempPath(), "randall-influence-" + Guid.NewGuid().ToString("N"));
        try
        {
            var payload = new byte[32];
            BitConverter.TryWriteBytes(payload.AsSpan(8), 0xDEADBEEFu);
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                regs: "rcx=00000000deadbeef\n");
            var chain = CorruptionChainBuilder.Build(id, "lab", null, obs, null, payload);

            InfluenceEngine.PersistForCrash(dir, id, "lab", null, null, obs, chain, payload: payload);
            var path = InfluenceEngine.PathFor(dir, id);
            Assert.True(File.Exists(path));
            Assert.EndsWith($"{id:N}_influence.json", path);

            var loaded = InfluenceEngine.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(id, loaded!.CrashId);
            Assert.True(loaded.Ok);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Build_consumes_external_evidence_facts()
    {
        var id = Guid.NewGuid();
        var external = new List<EvidenceFact>
        {
            new(
                "rc-fact-1",
                "Write AV at memcpy",
                "root_cause",
                null,
                EvidenceObservationType.Observed,
                0.9,
                DateTimeOffset.UtcNow),
        };

        var map = InfluenceEngine.Build(id, "lab", null, null, null, null, externalFacts: external);

        Assert.Contains(map.Facts, f => f.Name == "rc-fact-1");
    }
}
