using System.Diagnostics;
using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>Load expected sidecars and run live harness → dump → cdb for debugger-corpus cases.</summary>
internal static class DebuggerCorpusSupport
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    internal sealed record CorpusExpected(
        string CaseId,
        string? Description,
        bool Stub,
        CorpusExceptionExpected Exception,
        string Access,
        string AddressClass,
        string InputInfluence,
        CorpusHarnessExpected? Harness);

    internal sealed record CorpusExceptionExpected(
        string? Code,
        string? HintContains);

    internal sealed record CorpusHarnessExpected(
        string? Executable,
        string? Arg,
        string? AlternateTarget);

    internal static string CorpusRoot()
    {
        var root = CrashCatalog.FindRepoRoot()
                   ?? throw new InvalidOperationException("repo root not found");
        return Path.Combine(root, "tests", "debugger-corpus");
    }

    internal static string CaseDir(string caseId) => Path.Combine(CorpusRoot(), caseId);

    internal static CorpusExpected LoadExpected(string caseId)
    {
        var path = Path.Combine(CaseDir(caseId), "expected.json");
        Assert.True(File.Exists(path), $"missing expected.json for {caseId}");
        var expected = JsonSerializer.Deserialize<CorpusExpected>(File.ReadAllText(path), JsonOptions);
        Assert.NotNull(expected);
        return expected!;
    }

    internal static IEnumerable<string> AllCaseIds()
    {
        var root = CorpusRoot();
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            var name = Path.GetFileName(dir);
            if (name.StartsWith(".", StringComparison.Ordinal) || name.Equals("fixtures", StringComparison.OrdinalIgnoreCase))
                continue;
            if (File.Exists(Path.Combine(dir, "expected.json")))
                yield return name;
        }
    }

    internal static bool CanRunLiveCdbIntegration(out string? skipReason)
    {
        if (!OperatingSystem.IsWindows())
        {
            skipReason = "Windows only";
            return false;
        }

        if (DebuggerTools.FindCdb() is null)
        {
            skipReason = "cdb not installed";
            return false;
        }

        skipReason = null;
        return true;
    }

    internal static string HarnessExePath()
    {
        var root = CrashCatalog.FindRepoRoot()
                   ?? throw new InvalidOperationException("repo root not found");
        return Path.Combine(root, "targets", "debugger-corpus", "debugger_corpus_fault.exe");
    }

    internal static async Task<DebuggerObservation> RunCaseLiveAsync(
        string caseId,
        CancellationToken cancellationToken = default)
    {
        var expected = LoadExpected(caseId);
        Assert.False(expected.Stub, $"case {caseId} is stubbed");

        var exe = HarnessExePath();
        if (!File.Exists(exe))
            throw new InvalidOperationException(
                $"harness missing: {exe} — run scripts/build-debugger-corpus.ps1");

        var arg = expected.Harness?.Arg ?? caseId;
        var root = CrashCatalog.FindRepoRoot()!;
        var dumpsDir = Path.Combine(root, "data", "crashes", "debugger-corpus", "dumps");
        Directory.CreateDirectory(dumpsDir);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = arg,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };

        using var target = Process.Start(psi)
                           ?? throw new InvalidOperationException($"failed to start {exe}");

        using var watcher = ScreamWatcher.Start(target.Id, dumpsDir);
        var attached = await watcher.WaitUntilAttachedAsync(TimeSpan.FromSeconds(5), cancellationToken);
        if (!attached)
            throw new InvalidOperationException(
                $"Scream attach failed: {watcher.LastError ?? watcher.Phase}");

        var dumpTask = watcher.Completion;
        var finished = await Task.WhenAny(dumpTask, Task.Delay(TimeSpan.FromSeconds(20), cancellationToken));
        if (finished != dumpTask)
            throw new TimeoutException(
                $"timeout waiting for dump (phase={watcher.Phase}, err={watcher.LastError})");

        var dump = await dumpTask;
        if (dump is null || !File.Exists(dump) || new FileInfo(dump).Length == 0)
            throw new InvalidOperationException(
                $"no minidump captured (phase={watcher.Phase}, err={watcher.LastError})");

        var crashId = Guid.NewGuid();
        var crashesDir = Path.Combine(root, "data", "crashes", "debugger-corpus");
        Directory.CreateDirectory(crashesDir);

        // CdbProbePlan.StandardCrash via ScreamInvestigator → RANDFUZZ_* marker blocks.
        var obs = ScreamInvestigator.Investigate(crashesDir, crashId, dump, runExploitable: false, timeoutMs: 120_000);
        if (!obs.Ok)
            throw new InvalidOperationException(obs.Error ?? "ScreamInvestigator returned Ok=false");

        return obs;
    }

    internal static void AssertMatchesLoosely(CorpusExpected expected, DebuggerObservation obs)
    {
        var analyzeSidecar = TryReadAnalyzeSidecar(obs.ObservationPath);
        var exceptionBlob = string.Join('\n',
            obs.ExceptionCode ?? "",
            obs.ExceptionHint ?? "",
            obs.ExrText ?? "",
            obs.Diagnosis ?? "",
            analyzeSidecar ?? "");

        if (expected.Exception.Code is { } code)
        {
            Assert.Contains(code, exceptionBlob, StringComparison.OrdinalIgnoreCase);
        }

        if (expected.Exception.HintContains is { } hint)
        {
            Assert.Contains(hint, exceptionBlob, StringComparison.OrdinalIgnoreCase);
        }

        if (Enum.TryParse<DebuggerAccessKind>(expected.Access, ignoreCase: true, out var access))
            Assert.Equal(access, obs.Access);

        if (Enum.TryParse<DebuggerAddressClass>(expected.AddressClass, ignoreCase: true, out var addrClass))
        {
            if (obs.FaultAddressClass != addrClass && !AddressClassLooselyMatches(addrClass, obs))
                Assert.Equal(addrClass, obs.FaultAddressClass);
        }

        Assert.Equal(expected.InputInfluence, obs.SuspectedInputInfluence, StringComparer.OrdinalIgnoreCase);
    }

    private static bool AddressClassLooselyMatches(DebuggerAddressClass expected, DebuggerObservation obs)
    {
        if (expected == DebuggerAddressClass.NullPage
            && obs.FaultAddress is { } fa
            && ulong.TryParse(fa.Replace("0x", "", StringComparison.OrdinalIgnoreCase),
                System.Globalization.NumberStyles.HexNumber, null, out var v)
            && v < 0x1000)
            return true;

        if (expected == DebuggerAddressClass.Other
            && obs.FaultAddressClass is DebuggerAddressClass.Heapish or DebuggerAddressClass.Unknown)
            return true;

        if (expected == DebuggerAddressClass.AsciiPattern
            && obs.FaultAddressClass == DebuggerAddressClass.Other
            && obs.FaultAddress?.Contains("41414141", StringComparison.OrdinalIgnoreCase) == true)
            return true;

        return false;
    }

    internal static string? TryReadAnalyzeSidecar(string? observationPath)
    {
        if (string.IsNullOrWhiteSpace(observationPath))
            return null;
        var dir = Path.GetDirectoryName(observationPath);
        var name = Path.GetFileNameWithoutExtension(observationPath);
        if (dir is null || name is null || !name.EndsWith("_debugger_observation", StringComparison.Ordinal))
            return null;
        var analyzePath = Path.Combine(dir, name.Replace("_debugger_observation", "_analyze", StringComparison.Ordinal) + ".txt");
        return File.Exists(analyzePath) ? File.ReadAllText(analyzePath) : null;
    }
}
