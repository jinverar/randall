using System.Security.Principal;

namespace Randall.Infrastructure;

/// <summary>
/// Detect whether the current process token is elevated (Administrators).
/// Used to soft-skip pktmon / WPR before they dump scary access errors.
/// </summary>
public static class WindowsElevation
{
    public const string AdminHint =
        "Run agent/server as Administrator for pktmon/ETW";

    /// <summary>
    /// True when running elevated on Windows. Non-Windows → false.
    /// </summary>
    public static bool IsProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
#pragma warning disable CA1416 // Windows-only APIs gated by OperatingSystem.IsWindows above
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
#pragma warning restore CA1416
        }
        catch
        {
            return false;
        }
    }
}
