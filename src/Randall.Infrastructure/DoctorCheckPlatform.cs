using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Maps a doctor check <c>id</c> to a <see cref="PlatformScope"/> so results can be filtered to the
/// OS the user is fuzzing. Windows-only tooling (Sysinternals, WinDbg, pktmon, ETW, …) is tagged
/// <c>windows</c>; the Linux toolchain (<c>linux:*</c> ids) is tagged <c>linux</c>; protocol/model
/// and transport checks that apply everywhere stay <c>cross</c>.
/// </summary>
public static class DoctorCheckPlatform
{
    private static readonly HashSet<string> WindowsIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "procmon", "tcpvcon", "procdump", "procdumpOnCrash", "pktmon", "etw",
        "debugView", "sysinternalsSnapshots", "strings", "stringsOnCrash", "debuggerMode",
    };

    /// <summary>Classifies a check id. Prefixes (<c>debugger:</c>, <c>linux:</c>) are handled first.</summary>
    public static string Classify(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return PlatformScope.Cross;

        if (id.StartsWith("linux:", StringComparison.OrdinalIgnoreCase))
            return PlatformScope.Linux;

        // The debugger probe (scream/windbg/cdb/procdump) is the Windows crash-debugger stack.
        if (id.StartsWith("debugger:", StringComparison.OrdinalIgnoreCase))
            return PlatformScope.Windows;

        return WindowsIds.Contains(id) ? PlatformScope.Windows : PlatformScope.Cross;
    }
}
