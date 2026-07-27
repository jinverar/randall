using System.Diagnostics;
using System.Reflection;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Captures product version / git tip / build time for honesty stamps on investigation artifacts.
/// </summary>
public static class RandallBuildInfo
{
    public const string ProductVersion = "0.16.0-alpha";
    public const string AnalyzerLabel = "scream-investigator";
    public const string SchemaLabel = "research-artifacts-v1";

    private static readonly Lazy<RandallBuildIdentityDto> Cached = new(Capture);

    public static RandallBuildIdentityDto Current => Cached.Value;

    /// <summary>True when persisted engine is missing or differs from the running process.</summary>
    public static bool IsStale(RandallBuildIdentityDto? persisted)
    {
        if (persisted is null)
            return true;
        var live = Current;
        if (!string.IsNullOrWhiteSpace(live.GitCommit)
            && !string.IsNullOrWhiteSpace(persisted.GitCommit)
            && !string.Equals(live.GitCommit, persisted.GitCommit, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.Equals(live.Version, persisted.Version, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrWhiteSpace(live.InformationalVersion)
            && !string.IsNullOrWhiteSpace(persisted.InformationalVersion)
            && !string.Equals(live.InformationalVersion, persisted.InformationalVersion, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static RandallBuildIdentityDto Capture()
    {
        var asm = typeof(RandallBuildInfo).Assembly;
        var informational = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                            ?? asm.GetName().Version?.ToString()
                            ?? ProductVersion;
        var git = TryReadGitCommit() ?? TryParseGitFromInformational(informational);
        var buildTime = TryAssemblyBuildTime(asm);
        return new RandallBuildIdentityDto(
            ProductVersion,
            informational,
            git,
            buildTime,
            AnalyzerLabel,
            SchemaLabel);
    }

    private static string? TryParseGitFromInformational(string? informational)
    {
        if (string.IsNullOrWhiteSpace(informational))
            return null;
        // Common SourceLink shape: 1.2.3+abcdef0
        var plus = informational.LastIndexOf('+');
        if (plus < 0 || plus >= informational.Length - 1)
            return null;
        var hash = informational[(plus + 1)..].Trim();
        return hash.Length >= 7 ? hash[..Math.Min(12, hash.Length)] : null;
    }

    private static DateTimeOffset? TryAssemblyBuildTime(Assembly asm)
    {
        try
        {
            var path = asm.Location;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            return new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryReadGitCommit()
    {
        try
        {
            var repo = CrashCatalog.FindRepoRoot();
            if (repo is null)
                return null;
            var head = Path.Combine(repo, ".git", "HEAD");
            if (!File.Exists(head))
                return null;
            var text = File.ReadAllText(head).Trim();
            if (text.StartsWith("ref:", StringComparison.Ordinal))
            {
                var refPath = text["ref:".Length..].Trim().Replace('/', Path.DirectorySeparatorChar);
                var full = Path.Combine(repo, ".git", refPath);
                if (!File.Exists(full))
                    return null;
                text = File.ReadAllText(full).Trim();
            }

            return text.Length >= 7 ? text[..Math.Min(12, text.Length)] : text;
        }
        catch
        {
            return TryGitDescribe();
        }
    }

    private static string? TryGitDescribe()
    {
        try
        {
            var repo = CrashCatalog.FindRepoRoot();
            if (repo is null)
                return null;
            using var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "git",
                    Arguments = "rev-parse --short=12 HEAD",
                    WorkingDirectory = repo,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            if (!p.Start())
                return null;
            var output = p.StandardOutput.ReadToEnd().Trim();
            if (!p.WaitForExit(1500))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return null;
            }

            return p.ExitCode == 0 && output.Length >= 4 ? output : null;
        }
        catch
        {
            return null;
        }
    }
}
