namespace Randall.Infrastructure;

public static class WindowsExceptionHints
{
    public static string? Describe(int? exitCode)
    {
        if (exitCode is null)
            return null;

        return DescribeCode(unchecked((uint)exitCode.Value));
    }

    public static string? DescribeCode(uint code) =>
        code switch
        {
            0xC0000005 => "0xC0000005 ACCESS_VIOLATION",
            0xC0000008 => "0xC0000008 INVALID_HANDLE",
            0xC000001D => "0xC000001D ILLEGAL_INSTRUCTION",
            0xC0000094 => "0xC0000094 INTEGER_DIVIDE_BY_ZERO",
            0xC0000096 => "0xC0000096 PRIVILEGED_INSTRUCTION",
            0xC00000FD => "0xC00000FD STACK_OVERFLOW",
            0xC0000374 => "0xC0000374 HEAP_CORRUPTION",
            0xC0000409 => "0xC0000409 STACK_BUFFER_OVERRUN",
            0xC0000417 => "0xC0000417 INVALID_CRUNTIME_PARAMETER",
            0xC0000420 => "0xC0000420 ASSERTION_FAILURE",
            0x80000003 => "0x80000003 BREAKPOINT",
            0x80000004 => "0x80000004 SINGLE_STEP",
            0xE06D7363 => "0xE06D7363 C++ EH exception",
            0xE0434352 => "0xE0434352 CLR exception",
            >= 0x80000000 => $"NTSTATUS 0x{code:X8}",
            _ => null,
        };
}
