using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

public sealed record PageHeapEnableResult(bool Ok, bool Applied, string Message, string? GflagsPath);

/// <summary>
/// Enable Windows Page Heap for a target image (lab UAF detection).
/// Uses <c>gflags.exe</c> from Debugging Tools for Windows when present.
/// </summary>
public static class PageHeapEnabler
{
    public static PageHeapEnableResult TryEnableForExecutable(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            return new(false, false, "Executable not found for Page Heap", null);

        var image = Path.GetFileName(executablePath);
        if (string.IsNullOrWhiteSpace(image))
            return new(false, false, "Could not resolve image name", null);

        var gflags = FindGflags();
        if (gflags is null)
        {
            return new(true, false,
                "Page Heap requested but gflags.exe not found — install Debugging Tools for Windows, or enable manually: gflags /p /enable " +
                image + " /full",
                null);
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = gflags,
                Arguments = $"/p /enable {Escape(image)} /full",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
                return new(false, false, "Failed to start gflags", gflags);

            proc.WaitForExit(8000);
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            var text = (stdout + "\n" + stderr).Trim();

            if (proc.ExitCode != 0 && !Regex.IsMatch(text, "enabled|page heap", RegexOptions.IgnoreCase))
            {
                return new(false, false,
                    $"gflags failed (exit {proc.ExitCode}): {Truncate(text, 240)}", gflags);
            }

            return new(true, true,
                $"Page Heap enabled for {image} via gflags (/full). Disable later: gflags /p /disable {image}",
                gflags);
        }
        catch (Exception ex)
        {
            return new(false, false, $"gflags error: {ex.Message}", gflags);
        }
    }

    public static string? FindGflags()
    {
        var cdb = DebuggerTools.FindCdb();
        if (cdb is not null)
        {
            var sibling = Path.Combine(Path.GetDirectoryName(cdb)!, "gflags.exe");
            if (File.Exists(sibling))
                return sibling;
        }

        foreach (var root in new[]
                 {
                     @"C:\Program Files\Windows Kits\10\Debuggers\x64\gflags.exe",
                     @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe",
                     @"C:\Program Files\Windows Kits\10\Debuggers\x86\gflags.exe",
                 })
        {
            if (File.Exists(root))
                return root;
        }

        var pathDirs = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        foreach (var dir in pathDirs)
        {
            var p = Path.Combine(dir.Trim().Trim('"'), "gflags.exe");
            if (File.Exists(p))
                return p;
        }

        return null;
    }

    private static string Escape(string image) =>
        image.Contains(' ') ? $"\"{image}\"" : image;

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";
}
