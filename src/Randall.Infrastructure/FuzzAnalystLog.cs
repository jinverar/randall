using System.Text;

namespace Randall.Infrastructure;

/// <summary>Boofuzz-inspired analyst log lines for UI + console.</summary>
public static class FuzzAnalystLog
{
    static FuzzAnalystLog()
    {
        TryEnableAnsiConsole();
    }

    public static void Info(IFuzzProgressSink? sink, string message, int? iteration = null) =>
        Emit(sink, "info", $"Info: {message}", iteration);

    public static void Case(IFuzzProgressSink? sink, int iteration, string label) =>
        Emit(sink, "case", $"Test Case: {iteration}: {label}", iteration);

    public static void Step(IFuzzProgressSink? sink, string message, int? iteration = null) =>
        Emit(sink, "step", $"Test Step: {message}", iteration);

    public static void Tx(IFuzzProgressSink? sink, ReadOnlySpan<byte> payload, int? iteration = null)
    {
        var preview = HexPreview(payload);
        var msg = $"Transmitting {payload.Length} bytes: {preview}";
        Emit(sink, "tx", msg, iteration, payload.Length, preview);
    }

    public static void Ok(IFuzzProgressSink? sink, string message = "Check OK: No crash detected.", int? iteration = null) =>
        Emit(sink, "ok", message, iteration);

    public static void Warn(IFuzzProgressSink? sink, string message, int? iteration = null) =>
        Emit(sink, "warn", $"Info: {message}", iteration);

    public static void Crash(IFuzzProgressSink? sink, int iteration, string detail) =>
        Emit(sink, "crash", $"Error!!!! Crash Detected: {iteration}: {detail}", iteration);

    public static void Emit(
        IFuzzProgressSink? sink,
        string kind,
        string message,
        int? iteration = null,
        int? byteLength = null,
        string? hexPreview = null)
    {
        var at = DateTimeOffset.Now;
        var entry = new FuzzLogEvent(kind, message, at, iteration, byteLength, hexPreview);
        sink?.OnLog(entry);
        WriteConsole(kind, at, message);
    }

    public static string HexPreview(ReadOnlySpan<byte> data, int maxBytes = 24)
    {
        var n = Math.Min(data.Length, maxBytes);
        if (n <= 0) return "(empty)";
        var sb = new StringBuilder(n * 3 + 8);
        for (var i = 0; i < n; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[i].ToString("X2"));
        }

        if (data.Length > maxBytes)
            sb.Append(" …");
        return sb.ToString();
    }

    private static void WriteConsole(string kind, DateTimeOffset at, string message)
    {
        var ts = at.ToString("yyyy-MM-dd HH:mm:ss,fff");
        var (prefix, suffix) = kind switch
        {
            "case" => ("\x1b[33m", "\x1b[0m"),      // yellow
            "step" => ("\x1b[35m", "\x1b[0m"),      // magenta
            "tx" => ("\x1b[36m", "\x1b[0m"),        // cyan
            "ok" => ("\x1b[32m", "\x1b[0m"),        // green
            "crash" => ("\x1b[97;41m", "\x1b[0m"),  // white on red
            "warn" => ("\x1b[93m", "\x1b[0m"),      // bright yellow
            _ => ("\x1b[37m", "\x1b[0m"),           // gray/white
        };

        try
        {
            Console.WriteLine($"{prefix}[{ts}] {message}{suffix}");
        }
        catch
        {
            Console.WriteLine($"[{ts}] {message}");
        }
    }

    private static void TryEnableAnsiConsole()
    {
        if (!OperatingSystem.IsWindows())
            return;
        try
        {
            // Enable VT processing so color escapes work in conhost / Windows Terminal
            var stdout = GetStdHandle(-11);
            if (stdout == IntPtr.Zero || stdout == new IntPtr(-1))
                return;
            if (!GetConsoleMode(stdout, out var mode))
                return;
            const uint enableVirtualTerminal = 0x0004;
            _ = SetConsoleMode(stdout, mode | enableVirtualTerminal);
        }
        catch
        {
            /* ignore */
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
}
