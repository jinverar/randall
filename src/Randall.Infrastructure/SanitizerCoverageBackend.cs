using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// LLVM SanitizerCoverage (sancov) hook — complements DynamoRIO drcov when targets emit <c>*.sancov</c> PCs.
/// Select via <c>coverage.backend: sancov</c> or <c>fuzz.sanitizerCoverage: true</c>.
/// See docs/SANITIZER_COVERAGE.md.
/// </summary>
public static class SanitizerCoverageBackend
{
    private const ulong SancovMagic = 0xC0DEC0DEC0DEC0DEUL;

    public sealed record Status(
        bool Requested,
        bool Available,
        string Backend,
        string Note);

    public static Status Resolve(ProjectConfig project)
    {
        var cov = CoverageBackendResolver.Resolve(project);
        var requested = cov.PreferSancovIngest || project.Fuzz.SanitizerCoverage ||
                        cov.Requested is CoverageBackendResolver.Sancov;

        if (cov.SemanticOnly && !requested)
        {
            return new Status(
                false,
                false,
                CoverageBackendResolver.Semantic,
                cov.Note);
        }

        if (!requested)
        {
            return new Status(
                false,
                DynamoRioRunner.Discover().IsAvailable,
                cov.Effective,
                "SanitizerCoverage disabled — using stalk backends (DynamoRIO drcov when available). " +
                "Set coverage.backend: sancov or fuzz.sanitizerCoverage: true to ingest *.sancov.");
        }

        var dynamo = DynamoRioRunner.Discover();
        if (dynamo.IsAvailable && cov.Requested is not CoverageBackendResolver.Sancov)
        {
            return new Status(
                true,
                true,
                "drcov+sancov",
                "coverage.backend=" + cov.Requested + ": drcov active; also ingests *.sancov PCs from trace dir when present.");
        }

        if (dynamo.IsAvailable && cov.Requested is CoverageBackendResolver.Sancov)
        {
            return new Status(
                true,
                true,
                "sancov+drcov",
                cov.Note);
        }

        if (OperatingSystem.IsLinux() || cov.Requested is CoverageBackendResolver.Sancov)
        {
            return new Status(
                true,
                true,
                CoverageBackendResolver.Sancov,
                "Linux/sancov: build target with -fsanitize=address -fsanitize-coverage=trace-pc-guard " +
                "and set ASAN_OPTIONS=coverage=1 — Randfuzz ingests *.sancov from corpus/traces when DynamoRIO is absent. " +
                cov.Note);
        }

        return new Status(
            true,
            false,
            "none",
            "SanitizerCoverage requested but neither sancov artifacts nor DynamoRIO is available — corpus-novelty stalk only. " +
            "On Windows, sancov ingest needs ASan-built targets writing *.sancov under corpus/traces.");
    }

    /// <summary>
    /// Register raw PC edges from <c>*.sancov</c> files under a trace directory into the corpus edge set.
    /// Returns newly seen edge count (0 when no sancov files or parse failure).
    /// </summary>
    public static int TryIngestTraceDirectory(CoverageSet coverage, string? traceDir)
    {
        if (coverage is null || string.IsNullOrWhiteSpace(traceDir) || !Directory.Exists(traceDir))
            return 0;

        var newCount = 0;
        foreach (var file in Directory.EnumerateFiles(traceDir, "*.sancov", SearchOption.TopDirectoryOnly))
        {
            foreach (var edge in ParseSancovFile(file))
            {
                newCount += coverage.RegisterRawEdge(edge);
            }
        }

        return newCount;
    }

    internal static IEnumerable<string> ParseSancovFile(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch
        {
            yield break;
        }

        if (bytes.Length < 16)
            yield break;

        var module = Path.GetFileNameWithoutExtension(path);
        var offset = 0;

        if (bytes.Length >= 8)
        {
            var maybeMagic = BitConverter.ToUInt64(bytes, 0);
            if (maybeMagic == SancovMagic)
                offset = 8;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = offset; i + 8 <= bytes.Length; i += 8)
        {
            var pc = BitConverter.ToUInt64(bytes, i);
            if (pc is 0 or SancovMagic or > 0x0000_FFFF_FFFF_FFFF)
                continue;
            var edge = $"sancov:{module}:0x{pc:x}";
            if (seen.Add(edge))
                yield return edge;
        }
    }
}
