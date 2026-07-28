namespace Randall.Infrastructure;

/// <summary>
/// Append-only plain-text tee of the primary fuzz analyst console into the active run folder
/// (<c>data/runs/&lt;runId&gt;/fuzz-console.log</c>). Mirrors <see cref="FuzzAnalystLog"/> lines
/// without ANSI color codes so the file stays greppable.
/// </summary>
public sealed class FuzzRunConsoleLog : IDisposable
{
    public const string FileName = "fuzz-console.log";

    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private bool _disposed;

    public string Path { get; }

    private FuzzRunConsoleLog(string path)
    {
        Path = path;
        var stream = new FileStream(
            path,
            FileMode.Append,
            FileAccess.Write,
            FileShare.ReadWrite);
        _writer = new StreamWriter(stream) { AutoFlush = true };
    }

    /// <summary>
    /// Open (or append) <see cref="FileName"/> under <paramref name="runDirectory"/> and
    /// register as the process-wide session sink for <see cref="FuzzAnalystLog"/>.
    /// </summary>
    public static FuzzRunConsoleLog Attach(string runDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runDirectory);
        Directory.CreateDirectory(runDirectory);
        var path = System.IO.Path.Combine(runDirectory, FileName);
        var log = new FuzzRunConsoleLog(path);
        log.AppendBanner();
        FuzzAnalystLog.AttachSessionLog(log);
        return log;
    }

    public void Append(string kind, DateTimeOffset at, string message)
    {
        if (_disposed) return;
        var ts = at.ToString("yyyy-MM-dd HH:mm:ss,fff");
        var line = $"[{ts}] [{kind}] {message}";
        lock (_gate)
        {
            if (_disposed) return;
            try { _writer.WriteLine(line); }
            catch { /* never break fuzz on log I/O */ }
        }
    }

    /// <summary>Write a multi-line block (e.g. mutator leaderboard) with one timestamp.</summary>
    public void AppendPlain(string text)
    {
        if (_disposed || string.IsNullOrEmpty(text)) return;
        var ts = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
        lock (_gate)
        {
            if (_disposed) return;
            try
            {
                var first = true;
                foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
                {
                    if (first)
                    {
                        _writer.WriteLine($"[{ts}] {raw}");
                        first = false;
                    }
                    else
                        _writer.WriteLine(raw);
                }
            }
            catch { /* ignore */ }
        }
    }

    private void AppendBanner()
    {
        AppendPlain($"--- fuzz console log started {DateTimeOffset.UtcNow:O} UTC ---");
    }

    public void Dispose()
    {
        if (_disposed) return;
        FuzzAnalystLog.DetachSessionLog(this);
        lock (_gate)
        {
            if (_disposed) return;
            try
            {
                _writer.WriteLine(
                    $"--- fuzz console log ended {DateTimeOffset.UtcNow:O} UTC ---");
                _writer.Dispose();
            }
            catch { /* ignore */ }
            _disposed = true;
        }
    }
}
