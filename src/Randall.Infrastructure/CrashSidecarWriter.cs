using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class CrashSidecarWriter
{
    public static string Write(string crashesDir, CrashSidecarDto sidecar)
    {
        var path = Path.Combine(crashesDir, $"{sidecar.Project}_{sidecar.Iteration}_{sidecar.InputHash}_crash.json");
        File.WriteAllText(path, JsonSerializer.Serialize(sidecar, new JsonSerializerOptions { WriteIndented = true }));
        return path;
    }

    public static CrashSidecarDto? TryRead(string? sidecarPath)
    {
        if (string.IsNullOrWhiteSpace(sidecarPath) || !File.Exists(sidecarPath))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashSidecarDto>(File.ReadAllText(sidecarPath));
        }
        catch
        {
            return null;
        }
    }

    public static string? CopyTrace(string crashesDir, Guid crashId, string? sourceTracePath)
    {
        if (string.IsNullOrWhiteSpace(sourceTracePath) || !File.Exists(sourceTracePath))
            return null;

        var dir = Path.Combine(crashesDir, "traces");
        Directory.CreateDirectory(dir);
        var dest = Path.Combine(dir, $"{crashId:N}.log");
        File.Copy(sourceTracePath, dest, overwrite: true);
        return dest;
    }

    public static string? HexPreview(byte[]? bytes, int max = 128)
    {
        if (bytes is null || bytes.Length == 0)
            return null;
        var len = Math.Min(bytes.Length, max);
        var hex = string.Join(' ', bytes.AsSpan(0, len).ToArray().Select(b => b.ToString("X2")));
        if (bytes.Length > max)
            hex += " …";
        return hex;
    }
}
