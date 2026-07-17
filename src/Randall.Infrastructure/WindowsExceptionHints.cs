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
            0xC0000409 => "0xC0000409 STACK_BUFFER_OVERRUN",
            0xC000001D => "0xC000001D ILLEGAL_INSTRUCTION",
            0xC0000094 => "0xC0000094 INTEGER_DIVIDE_BY_ZERO",
            0xC00000FD => "0xC00000FD STACK_OVERFLOW",
            >= 0x80000000 => $"NTSTATUS 0x{code:X8}",
            _ => null,
        };
}
