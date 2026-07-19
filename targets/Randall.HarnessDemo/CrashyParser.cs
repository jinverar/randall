using System.Text;
using Randall.Contracts;

namespace Randall.HarnessDemo;

/// <summary>
/// Minimal demo of harness design principles (docs/HARNESS_DESIGN.md).
/// <para>
/// Session state: reusable scratch buffer (cleared each Reset).<br/>
/// Iteration state: parse cursor / flags — wiped in Reset.<br/>
/// Target: <see cref="ToyParser"/> rejects invalid input; a deliberate bug
/// throws on a specific pattern (crash transparency). The harness does not filter.
/// </para>
/// </summary>
public sealed class CrashyParser : IInProcessHarnessLifecycle, IInProcessHarnessReset
{
    // ----- Session state (Initialize → Shutdown) -----
    private byte[]? _scratch;
    private ToyParser? _parser;

    // ----- Iteration state (Reset every case) -----
    private int _iterationCalls; // metric only; not used for control flow

    public void Initialize()
    {
        _scratch = new byte[4096];
        _parser = new ToyParser();
        _iterationCalls = 0;
    }

    public void Shutdown()
    {
        _parser = null;
        _scratch = null;
    }

    public void Reset()
    {
        // No persistent side effects: wipe scratch and per-case counters.
        if (_scratch is not null)
            Array.Clear(_scratch);
        _iterationCalls = 0;
        _parser?.Reset();
    }

    public int FuzzOne(ReadOnlySpan<byte> data)
    {
        _iterationCalls++;
        var parser = _parser ?? throw new InvalidOperationException("Initialize not called");

        // Controlled mapping: copy into scratch when it fits; if larger, pass a
        // sliced view — still reach the target (honest reachability). Never "return 0"
        // just because length looks wrong — ToyParser rejects that itself.
        ReadOnlySpan<byte> view = data;
        if (_scratch is not null && data.Length <= _scratch.Length)
        {
            data.CopyTo(_scratch);
            view = _scratch.AsSpan(0, data.Length);
        }

        // Single responsibility: call target. Do not catch — crash transparency.
        var status = parser.Parse(view);
        _ = _iterationCalls;
        _ = status;
        return 0; // 0 = completed, including Reject
    }
}

/// <summary>
/// Stand-in "target" library. Rejects invalid input; throws only on the bug path.
/// </summary>
internal sealed class ToyParser
{
    private bool _dirty;

    public void Reset() => _dirty = false;

    /// <summary>
    /// Returns Reject for structurally invalid input (not a crash).
    /// Throws on the deliberate bug when payload starts with ASCII "CRASH"
    /// after a valid 2-byte type tag — simulates a real parser fault.
    /// </summary>
    public ParseStatus Parse(ReadOnlySpan<byte> data)
    {
        if (_dirty)
            throw new InvalidOperationException("parser used without Reset — harness bug");

        _dirty = true;

        // Target rejects — not the harness.
        if (data.Length < 2)
            return ParseStatus.Reject;

        var type = (char)data[0];
        if (type is not ('A' or 'B' or 'C'))
            return ParseStatus.Reject;

        var body = data[2..];
        // Bug path: honest reachability — fuzzer can hit this via dictionary/mutations.
        if (body.StartsWith("CRASH"u8))
        {
            throw new InvalidOperationException(
                "toy bug: body starts with CRASH (" +
                Encoding.ASCII.GetString(data[..Math.Min(data.Length, 32)]) + ")");
        }

        // Cheap work
        var sum = 0;
        foreach (var b in body)
            sum = (sum + b) * 31;
        return sum == int.MinValue ? ParseStatus.Ok : ParseStatus.Ok;
    }
}

internal enum ParseStatus
{
    Ok,
    Reject,
}
