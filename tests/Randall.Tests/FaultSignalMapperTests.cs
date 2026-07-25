using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class FaultSignalMapperTests
{
    [Fact]
    public void FromCrash_TriageAndCdb_ProducesMultipleSignals()
    {
        var triage = new CrashTriageDto(
            "access_violation", "high", "AV @ 0xdead", true, false, "p|av|dead",
            "AV", "0xDEAD", "vuln.exe", "0x401000", "0x7fff0010");

        var cdb = new CdbTriageDto(
            true, "EXPLOITABLE", "stack buffer overrun", null, null, null, true, null);

        var signals = FaultSignalMapper.FromCrash(triage, null, cdb, null, pageHeapEnabled: true);

        Assert.Contains(signals, s => s.Kind == FaultSignalKind.AccessViolation);
        Assert.Contains(signals, s => s.Kind == FaultSignalKind.WerClassification);
        Assert.Contains(signals, s => s.Kind == FaultSignalKind.PageHeap);
        Assert.Equal(FaultSignalKind.WerClassification, FaultSignalMapper.Primary(signals)!.Kind);
    }

    [Fact]
    public void FromCrash_SanitizerDetail_AddsSanitizerSignal()
    {
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run", 1, "p", "cmd", "m", [], null, "seed", [],
            "hash", "path", 10, 1, null, "heap-buffer-overflow in foo", null, 0, 0,
            "none", null, null, null, null,
            new TransportSnapshotDto("file", "", 0, false),
            new FuzzSnapshotDto(false, false, "projects/x.yaml"),
            DateTimeOffset.UtcNow);

        var signals = FaultSignalMapper.FromCrash(null, null, null, sidecar);

        Assert.Single(signals);
        Assert.Equal(FaultSignalKind.Sanitizer, signals[0].Kind);
        Assert.Equal(FaultSignalSource.SanitizerLog, signals[0].Source);
    }

    [Fact]
    public void FromOracleFinding_RuntimeCrash_MapsFault()
    {
        var fault = FaultSignalMapper.FromOracleFinding(
            "runtime.crash", "runtime", "crashed exit=-1", 0.99);

        Assert.NotNull(fault);
        Assert.Equal(FaultSignalKind.AccessViolation, fault!.Kind);
        Assert.Equal(FaultSignalSource.OracleRuntime, fault.Source);
    }
}
