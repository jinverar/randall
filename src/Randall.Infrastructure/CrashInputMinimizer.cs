using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Optional crash-input minimizer — tail trim + chunk removal via live replay.
/// Used before Deep Scream mark when <c>fuzz.deepScreamAutoMinimize</c> is on.
/// </summary>
public static class CrashInputMinimizer
{
    public const int DefaultMaxSteps = 48;

    public static string MinimizedPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_minimized.bin");

    public static async Task<CrashMinimizeResult> TryMinimizeAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        string crashesDir,
        Guid crashId,
        int maxSteps = DefaultMaxSteps,
        CancellationToken cancellationToken = default)
    {
        if (payload.Length < 8)
            return CrashMinimizeResult.Skipped("input too short");

        var engine = new ReplayEngine();
        var baseline = await engine.ReplayAsync(project, yamlPath, payload, cancellationToken);
        if (!baseline.Crashed)
            return CrashMinimizeResult.Skipped("baseline replay did not crash");

        var best = payload.ToArray();
        var steps = 0;

        // Tail trim — cheap wins first.
        for (var trim = best.Length / 4; trim >= 4 && steps < maxSteps; trim = Math.Max(4, trim / 2))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = best.AsSpan(0, best.Length - trim).ToArray();
            steps++;
            if (!await StillCrashesAsync(engine, project, yamlPath, candidate, cancellationToken))
                continue;
            best = candidate;
        }

        // Remove fixed-size chunks from the middle.
        var chunk = Math.Max(4, best.Length / 8);
        for (var start = 0; start + chunk < best.Length && steps < maxSteps; start += chunk)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var candidate = new byte[best.Length - chunk];
            Buffer.BlockCopy(best, 0, candidate, 0, start);
            Buffer.BlockCopy(best, start + chunk, candidate, start, best.Length - start - chunk);
            steps++;
            if (!await StillCrashesAsync(engine, project, yamlPath, candidate, cancellationToken))
                continue;
            best = candidate;
            start = Math.Max(-chunk, start - chunk);
        }

        if (best.Length >= payload.Length)
            return new CrashMinimizeResult(true, false, payload.Length, payload.Length, steps, null, "no shrink");

        Directory.CreateDirectory(crashesDir);
        var outPath = MinimizedPathFor(crashesDir, crashId);
        await File.WriteAllBytesAsync(outPath, best, cancellationToken);
        return new CrashMinimizeResult(
            true,
            true,
            payload.Length,
            best.Length,
            steps,
            outPath,
            $"shrunk {payload.Length}→{best.Length} bytes ({steps} replays)");
    }

    private static async Task<bool> StillCrashesAsync(
        ReplayEngine engine,
        ProjectConfig project,
        string yamlPath,
        byte[] candidate,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await engine.ReplayAsync(project, yamlPath, candidate, cancellationToken);
            return result.Crashed;
        }
        catch
        {
            return false;
        }
    }
}

public sealed record CrashMinimizeResult(
    bool Attempted,
    bool Succeeded,
    int OriginalLength,
    int ResultLength,
    int ReplaySteps,
    string? OutputPath,
    string Summary)
{
    public static CrashMinimizeResult Skipped(string reason) =>
        new(false, false, 0, 0, 0, null, reason);
}
