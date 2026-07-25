using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Soft hook for LLVM SanitizerCoverage (sancov) as an alternative/complement to DynamoRIO drcov.
/// Today: reports availability and defers to drcov when sancov is not wired. See docs/SANITIZER_COVERAGE.md.
/// </summary>
public static class SanitizerCoverageBackend
{
    public sealed record Status(
        bool Requested,
        bool Available,
        string Backend,
        string Note);

    public static Status Resolve(ProjectConfig project)
    {
        var requested = project.Fuzz.SanitizerCoverage;
        if (!requested)
        {
            return new Status(
                false,
                DynamoRioRunner.Discover().IsAvailable,
                "drcov",
                "SanitizerCoverage disabled — using stalk backends (DynamoRIO drcov when available).");
        }

        var dynamo = DynamoRioRunner.Discover();
        if (dynamo.IsAvailable)
        {
            return new Status(
                true,
                true,
                "drcov-fallback",
                "fuzz.sanitizerCoverage is a stub — sancov ingest not wired yet; DynamoRIO drcov remains active.");
        }

        return new Status(
            true,
            false,
            "none",
            "SanitizerCoverage requested but neither sancov nor DynamoRIO is available — corpus-novelty stalk only.");
    }
}
