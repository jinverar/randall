using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Opt-in Sysinternals Strings on a crashing input / last payload.
/// Soft-fails when <c>strings64.exe</c> is missing.
/// </summary>
public static class StringsOnCrash
{
    public static string? TryCapture(
        string inputPath,
        string? outputPath = null,
        string? repoRoot = null,
        int maxBytes = 2_000_000)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
            return null;

        var exe = SysinternalsToolPaths.FindStrings(repoRoot);
        if (exe is null)
            return null;

        outputPath ??= Path.Combine(
            Path.GetDirectoryName(inputPath) ?? ".",
            Path.GetFileNameWithoutExtension(inputPath) + "_strings.txt");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                // -n 4: printable runs of length >= 4; -accepteula for headless
                Arguments = $"-accepteula -n 4 \"{inputPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
                return null;

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);

            if (stdout.Length > maxBytes)
                stdout = stdout[..maxBytes] + "\n# truncated\n";

            var body = new StringBuilder();
            body.AppendLine($"# {Path.GetFileName(exe)} -accepteula -n 4 \"{inputPath}\"");
            body.AppendLine($"# exit={proc.ExitCode} utc={DateTimeOffset.UtcNow:O}");
            if (!string.IsNullOrWhiteSpace(stderr))
                body.AppendLine($"# stderr: {stderr.Trim()}");
            body.AppendLine(stdout);
            File.WriteAllText(outputPath, body.ToString());
            return outputPath;
        }
        catch
        {
            return null;
        }
    }
}
