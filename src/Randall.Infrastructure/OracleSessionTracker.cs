using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Tracks semantic session facts across a fuzz run (auth markers, prior commands/responses).
/// Reset when the long-lived target crashes/restarts.
/// </summary>
public sealed class OracleSessionTracker
{
    private readonly HashSet<string> _commands = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _responseMarkers = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _authMarkers = [];

    public bool Authenticated { get; private set; }
    public string State { get; private set; } = "START";
    public IReadOnlyCollection<string> SeenCommands => _commands;
    public IReadOnlyCollection<string> SeenResponseMarkers => _responseMarkers;

    public void ConfigureAuthMarkers(OracleConfig cfg)
    {
        _authMarkers.Clear();
        foreach (var a in cfg.Auth)
        {
            if (!string.IsNullOrWhiteSpace(a.UntilResponse))
                _authMarkers.Add(a.UntilResponse!);
        }
        foreach (var s in cfg.State)
        {
            if (!string.IsNullOrWhiteSpace(s.UntilResponse))
                _authMarkers.Add(s.UntilResponse!);
            if (!string.IsNullOrWhiteSpace(s.PriorResponse))
                _authMarkers.Add(s.PriorResponse!);
        }
    }

    public void Reset()
    {
        _commands.Clear();
        _responseMarkers.Clear();
        Authenticated = false;
        State = "START";
    }

    /// <summary>Call after each iteration (and after oracle eval) to advance session facts.</summary>
    /// <summary>
    /// Credit prior steps in a session flow/graph that already succeeded on this connection
    /// (so REQUEST after BIND in the same iteration sees BIND_ACK).
    /// </summary>
    public void NotePriorStep(string? commandName, string? expectResponse)
    {
        RememberCommand(commandName);
        if (!string.IsNullOrWhiteSpace(expectResponse))
            RememberResponseMarker(expectResponse!);
    }

    public void Observe(string? commandName, TargetRunResult result)
    {
        RememberCommand(commandName);

        var text = ResponseText(result.ResponseBytes);
        if (text.Length == 0)
            return;

        foreach (var marker in _authMarkers)
        {
            if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                RememberResponseMarker(marker);
        }

        // Generic response class token
        var token = ResponseMatcher.Describe(result.ResponseBytes, 40);
        if (!string.IsNullOrWhiteSpace(token) && token != "(no response)")
            _responseMarkers.Add(token);
    }

    private void RememberCommand(string? commandName)
    {
        if (string.IsNullOrWhiteSpace(commandName))
            return;
        var cmd = commandName.Split('/')[0];
        if (cmd.StartsWith("flow/", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["flow/".Length..];
        if (cmd.StartsWith("graph/", StringComparison.OrdinalIgnoreCase))
            cmd = cmd["graph/".Length..];
        _commands.Add(cmd);
        var leaf = commandName.Contains('/') ? commandName[(commandName.LastIndexOf('/') + 1)..] : commandName;
        if (!string.IsNullOrWhiteSpace(leaf))
            _commands.Add(leaf);
    }

    private void RememberResponseMarker(string marker)
    {
        _responseMarkers.Add(marker);
        if (_authMarkers.Any(m => marker.Contains(m, StringComparison.OrdinalIgnoreCase) ||
                                  m.Contains(marker, StringComparison.OrdinalIgnoreCase)))
        {
            Authenticated = true;
            State = "AUTHENTICATED";
        }
    }

    public bool HasCommand(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;
        return _commands.Any(c => c.Contains(name, StringComparison.OrdinalIgnoreCase) ||
                                  name.Contains(c, StringComparison.OrdinalIgnoreCase));
    }

    public bool HasResponseMarker(string? marker)
    {
        if (string.IsNullOrWhiteSpace(marker))
            return false;
        if (_responseMarkers.Any(m => m.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            return true;
        return false;
    }

    public string Snapshot() =>
        $"state={State}; auth={Authenticated}; cmds={string.Join(',', _commands.Take(8))}";

    private static string ResponseText(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
            return "";
        try { return Encoding.ASCII.GetString(bytes); }
        catch { return ""; }
    }
}
