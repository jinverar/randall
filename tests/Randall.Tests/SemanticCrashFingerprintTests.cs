using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class SemanticCrashFingerprintTests
{
    [Fact]
    public void Build_includes_exception_access_function_and_offset()
    {
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\nFAULTING_IP: 41414141\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rip=0000000041414141\n",
            stack: """
                00000000`0012ff00 00000000`00401000 vuln!HandleHello+0x42
                00000000`0012ff08 00000000`00402000 vuln!Parse+0x10
                """);

        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 1, "lab", "CMD", "expand", ["expand"], null, "seed", [],
            "abc", "x.bin", payload.Length, -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("stdio", "", 0, false),
            new FuzzSnapshotDto(false, false, "projects/x.yaml"),
            DateTimeOffset.UtcNow);
        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: obs);

        Assert.Contains("exc=access_violation", triage.SemanticFingerprint!, StringComparison.Ordinal);
        Assert.Contains("acc=write", triage.SemanticFingerprint!, StringComparison.Ordinal);
        Assert.Contains("addr=asciipattern", triage.SemanticFingerprint!, StringComparison.Ordinal);
        Assert.Contains("fn=vuln!handlehello", triage.SemanticFingerprint!, StringComparison.Ordinal);
        Assert.Contains("stk=vuln!handlehello>vuln!parse", triage.SemanticFingerprint!, StringComparison.Ordinal);
        Assert.Contains("off=0x28", triage.SemanticFingerprint!, StringComparison.Ordinal);
    }

    [Fact]
    public void Build_includes_oracle_violation_and_coverage_tail()
    {
        var id = Guid.NewGuid();
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "CMD", "havoc", ["havoc"], null, "seed", [],
            "abc", "x.bin", 64, -1073741819, "AV", "state auth violation", null, 5, 100, "drcov",
            null, null, null, null,
            new TransportSnapshotDto("stdio", "", 0, false),
            new FuzzSnapshotDto(false, false, "projects/x.yaml"),
            DateTimeOffset.UtcNow,
            null,
            new OracleScore(65, [new OracleScoreTerm("state violation", 35, "auth mismatch")], "+35 state violation"));

        var fp = SemanticCrashFingerprint.Build("access_violation", sidecar: sidecar);

        Assert.Contains("ora=state-violation", fp, StringComparison.Ordinal);
        Assert.Contains("cov=tail-mid", fp, StringComparison.Ordinal);
    }

    [Fact]
    public void Build_chain_signature_changes_with_corruption_chain()
    {
        var chainA = new CrashCorruptionChainDto(
            true, Guid.NewGuid(), "lab", "HIGH", "expand → write AV", "payload", "expand",
            40, "RIP dword", ["expand"], [new CorruptionChainStepDto(1, "mutation", "expand")],
            null, null, DateTimeOffset.UtcNow);
        var chainB = chainA with { Summary = "havoc → read AV" };

        var fpA = SemanticCrashFingerprint.Build("access_violation", corruptionChain: chainA);
        var fpB = SemanticCrashFingerprint.Build("access_violation", corruptionChain: chainB);

        Assert.NotEqual(fpA, fpB);
        Assert.Contains("chain=", fpA, StringComparison.Ordinal);
        Assert.DoesNotContain("chain=none", fpA, StringComparison.Ordinal);
    }

    [Fact]
    public void ClusterGroupKey_prefers_semantic_fingerprint()
    {
        var triage = new CrashTriageDto(
            "access_violation", "high", "s", false, false, "legacy-key",
            null, null, null, null, null,
            SemanticFingerprint: "exc=access_violation:acc=write:fn=unk");

        Assert.Equal("exc=access_violation:acc=write:fn=unk", SemanticCrashFingerprint.ClusterGroupKey(triage));
    }

    [Fact]
    public void ClusterGroupKey_falls_back_to_cluster_key()
    {
        var triage = new CrashTriageDto(
            "access_violation", "high", "s", false, false, "legacy-key",
            null, null, null, null, null);

        Assert.Equal("legacy-key", SemanticCrashFingerprint.ClusterGroupKey(triage));
    }

    [Fact]
    public void BuildClusterKey_remains_backward_compatible()
    {
        var baseKey = CrashTriage.BuildClusterKey("proj", "access_violation", "0x41414141", "vuln.exe");
        Assert.Equal(baseKey, CrashTriage.BuildClusterKey("proj", "access_violation", "0x41414141", "vuln.exe", null));
    }
}
