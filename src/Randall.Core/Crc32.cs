namespace Randall.Core;

/// <summary>ISO HDLC / Ethernet-style CRC32 (polynomial 0xEDB88320).</summary>
public static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    public static void Write(Span<byte> dest, uint value, bool littleEndian)
    {
        if (littleEndian)
        {
            dest[0] = (byte)value;
            dest[1] = (byte)(value >> 8);
            dest[2] = (byte)(value >> 16);
            dest[3] = (byte)(value >> 24);
        }
        else
        {
            dest[0] = (byte)(value >> 24);
            dest[1] = (byte)(value >> 16);
            dest[2] = (byte)(value >> 8);
            dest[3] = (byte)value;
        }
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (var j = 0; j < 8; j++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }
}
