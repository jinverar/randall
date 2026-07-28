using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// A-B-A determinism probe for persistent harness Reset() — same input twice with Reset between
/// should yield identical crash/exit classification.
/// </summary>
internal static class HarnessDeterminismProbe
{
    public sealed record ProbeResult(bool Ok, bool DisabledPersistent, string Message);

    public static ProbeResult Run(ManagedHarnessHost host, bool strict, byte[]? probeInput = null)
    {
        if (!host.SupportsReset)
            return new ProbeResult(true, false, "no Reset — skip A-B-A");

        probeInput ??= "RANDALL_ABA_PROBE\0"u8.ToArray();

        host.Reset();
        var a = host.Run(probeInput);
        host.Reset();
        var b = host.Run(probeInput);

        var same = a.Crashed == b.Crashed &&
                   a.ExitCode == b.ExitCode &&
                   string.Equals(Normalize(a.Detail), Normalize(b.Detail), StringComparison.Ordinal);

        if (same)
            return new ProbeResult(true, false, "A-B-A Reset probe OK");

        var msg =
            $"Harness Reset() failed A-B-A determinism probe " +
            $"(A crashed={a.Crashed}/exit={a.ExitCode} vs B crashed={b.Crashed}/exit={b.ExitCode}). " +
            "Persistent mode may poison state across cases.";

        if (strict)
            throw new InvalidOperationException(msg + " (fuzz.harnessStrict: true)");

        return new ProbeResult(false, true, msg + " — disabling persistent for this session.");
    }

    private static string Normalize(string? detail)
    {
        if (string.IsNullOrWhiteSpace(detail))
            return "";
        // Strip timing / iteration suffixes that InProcessSession appends after Run.
        var idx = detail.IndexOf(" [", StringComparison.Ordinal);
        return idx >= 0 ? detail[..idx] : detail;
    }
}
