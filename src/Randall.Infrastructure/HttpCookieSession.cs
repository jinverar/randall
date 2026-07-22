namespace Randall.Infrastructure;

/// <summary>
/// Per-fuzz-run cookie jar storage (AsyncLocal). Call <see cref="Begin"/> at campaign start
/// and <see cref="End"/> when done. Pure helpers live in <see cref="HttpCookieJar"/>.
/// </summary>
public static class HttpCookieSession
{
    private static readonly AsyncLocal<Dictionary<string, string>?> Current = new();

    public static void Begin() => Current.Value = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public static void End() => Current.Value = null;

    public static bool TryGet(out Dictionary<string, string> jar)
    {
        jar = Current.Value!;
        return jar is not null;
    }

    public static IReadOnlyDictionary<string, string> Snapshot() =>
        Current.Value is { } j
            ? new Dictionary<string, string>(j, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
