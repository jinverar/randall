using System.Text.Json;

namespace Randall.Infrastructure;

/// <summary>
/// Soft-read / quarantine helpers for research JSON sidecars (<c>*_*.json</c>).
/// Corrupt / torn / NUL-padded files return null and are moved aside — never throw, never invent data.
/// </summary>
public static class ResearchSidecarIO
{
    public static T? TryRead<T>(string? path, JsonSerializerOptions? options = null) where T : class
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ResearchSidecar] warn: cannot read {path}: {ex.Message}");
            return null;
        }

        if (IsCorruptJson(text))
        {
            Quarantine(path, text, "corrupt/partial");
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(text, options);
        }
        catch (Exception ex)
        {
            Quarantine(path, text, ex.Message);
            return null;
        }
    }

    public static void WriteAtomic(string path, string contents) =>
        AtomicFile.WriteAllText(path, contents);

    internal static bool IsCorruptJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return true;
        if (text.Contains('\0'))
            return true;
        var trimmed = text.TrimStart();
        if (trimmed.Length == 0)
            return true;
        var c = trimmed[0];
        return c is not ('{' or '[' or '"' or '-' or 't' or 'f' or 'n')
               && !char.IsDigit(c);
    }

    private static void Quarantine(string path, string text, string reason)
    {
        try
        {
            var dest = path + ".corrupt";
            var stamp = DateTimeOffset.UtcNow.ToString("o");
            var header = $"# quarantined {stamp} reason={reason}{Environment.NewLine}";
            File.AppendAllText(dest, header + text + Environment.NewLine);
            try { File.Delete(path); }
            catch
            {
                // If delete fails (locked), leave original — next read will soft-null again.
            }

            Console.Error.WriteLine(
                $"[ResearchSidecar] warn: quarantined corrupt sidecar → {dest}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[ResearchSidecar] warn: quarantine failed for {path}: {ex.Message}");
        }
    }
}
