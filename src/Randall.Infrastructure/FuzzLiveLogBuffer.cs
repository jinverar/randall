namespace Randall.Infrastructure;

/// <summary>
/// Ring buffer of analyst log lines for reconnect / page-refresh replay.
/// Mirrors the client-side <c>LOG_BUFFER_MAX</c> cap in app.js.
/// </summary>
public sealed class FuzzLiveLogBuffer
{
    public const int MaxEntries = 2000;

    private readonly object _gate = new();
    private readonly Queue<FuzzLogEvent> _entries = new();

    public void Clear()
    {
        lock (_gate)
            _entries.Clear();
    }

    public void Append(FuzzLogEvent entry)
    {
        lock (_gate)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > MaxEntries)
                _entries.Dequeue();
        }
    }

    public IReadOnlyList<FuzzLogEvent> Snapshot()
    {
        lock (_gate)
            return _entries.ToList();
    }
}
