namespace Randall.Infrastructure;

/// <summary>
/// Reads (and explains how to set) the Linux kernel ASLR mode via
/// <c>/proc/sys/kernel/randomize_va_space</c>: 0 = off, 1 = partial (stack/mmap/vDSO),
/// 2 = full (adds the heap). Setting it requires root, so this only reports state and returns the
/// command to change it; use <c>setarch -R</c> to disable ASLR for a single process run.
/// </summary>
public static class AslrControl
{
    private const string ProcPath = "/proc/sys/kernel/randomize_va_space";

    public sealed record AslrState(int? Value, string Label, string HowToChange);

    public static AslrState Read()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists(ProcPath))
            return new AslrState(null, "unknown (not Linux)", "n/a");

        try
        {
            var raw = File.ReadAllText(ProcPath).Trim();
            var value = int.TryParse(raw, out var v) ? v : (int?)null;
            return new AslrState(value, Label(value),
                "sudo sysctl kernel.randomize_va_space=2  (on/full) | =0 (off);  per-run: setarch -R <exe>");
        }
        catch
        {
            return new AslrState(null, "unreadable", "sudo sysctl kernel.randomize_va_space=<0|1|2>");
        }
    }

    private static string Label(int? v) => v switch
    {
        0 => "off",
        1 => "partial (stack/mmap/vDSO)",
        2 => "full (stack/mmap/vDSO/heap)",
        null => "unknown",
        _ => $"mode {v}",
    };
}
