namespace Randall.Infrastructure;

/// <summary>
/// NetBIOS session message helpers (SMB-over-TCP framing).
/// Type 0x00 + 24-bit big-endian length covers the SMB PDU that follows.
/// </summary>
public static class NbssFraming
{
    /// <summary>
    /// When <paramref name="message"/> looks like an NBSS session message, rewrite the
    /// 24-bit length so it matches the trailing payload. Returns the same instance when
    /// unchanged; otherwise a copy with a corrected length.
    /// </summary>
    public static byte[] TrySyncLength(byte[] message)
    {
        if (message.Length < 4 || message[0] != 0)
            return message;

        var payloadLen = message.Length - 4;
        if (payloadLen is < 0 or > 0xFFFFFF)
            return message;

        var b1 = (byte)((payloadLen >> 16) & 0xFF);
        var b2 = (byte)((payloadLen >> 8) & 0xFF);
        var b3 = (byte)(payloadLen & 0xFF);
        if (message[1] == b1 && message[2] == b2 && message[3] == b3)
            return message;

        var copy = (byte[])message.Clone();
        copy[1] = b1;
        copy[2] = b2;
        copy[3] = b3;
        return copy;
    }

    /// <summary>
    /// True when the mutated field is the NBSS length itself — leave it desynced so
    /// length-mismatch bugs stay reachable.
    /// </summary>
    public static bool IsNbssLengthField(string? fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
            return false;
        return fieldName.Contains("nbss_len", StringComparison.OrdinalIgnoreCase)
               || fieldName.Equals("nbss_length", StringComparison.OrdinalIgnoreCase);
    }
}
