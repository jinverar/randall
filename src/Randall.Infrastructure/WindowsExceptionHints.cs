namespace Randall.Infrastructure;

public static class WindowsExceptionHints
{
    public static string? Describe(int? exitCode)
    {
        if (exitCode is null)
            return null;

        return exitCode.Value switch
        {
            unchecked((int)0xC0000005) => "0xC0000005 ACCESS_VIOLATION",
            unchecked((int)0xC0000409) => "0xC0000409 STACK_BUFFER_OVERRUN",
            unchecked((int)0xC000001D) => "0xC000001D ILLEGAL_INSTRUCTION",
            unchecked((int)0xC0000094) => "0xC0000094 INTEGER_DIVIDE_BY_ZERO",
            unchecked((int)0xC00000FD) => "0xC00000FD STACK_OVERFLOW",
            < 0 => $"NTSTATUS 0x{exitCode.Value & 0xFFFFFFFF:X8}",
            _ => null,
        };
    }
}
