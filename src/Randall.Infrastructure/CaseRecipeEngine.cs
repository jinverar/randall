using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// CyberChef-style case recipes inspired by Sulley blocks (static/string/delim)
/// and AFL seed/dictionary practice — build bytes, then mutate in the fuzzer.
/// </summary>
public static class CaseRecipeEngine
{
    public static IReadOnlyList<CaseOpDto> ListOps() =>
    [
        new("static", "Static text", "Literal UTF-8 — Sulley s_static (keep as-is in seed)", "text",
            ["value", "role"]),
        new("text", "Text / string", "UTF-8 string — Sulley s_string (good dictionary hint)", "text",
            ["value", "role"]),
        new("delim", "Delimiter", "Space, colon, slash, CRLF, … — Sulley s_delim", "text",
            ["value", "role"]),
        new("hex", "Hex bytes", "Raw bytes from hex (spaces/dashes ok)", "binary",
            ["value"]),
        new("repeat", "Repeat", "Repeat a byte/char N times (AAAA…)", "binary",
            ["value", "count"]),
        new("random", "Random bytes", "N cryptographically random bytes", "binary",
            ["count"]),
        new("interesting", "Interesting int", "AFL-style interesting 8/16/32-bit value", "binary",
            ["format", "value"]),
        new("null", "Null byte", "Single 0x00", "binary", []),
        new("crlf", "CRLF", "\\r\\n", "text", []),
        new("lf", "LF", "Single \\n", "text", []),
        new("base64", "Base64 decode", "Decode base64 into bytes", "binary",
            ["value"]),
        new("utf16", "UTF-16LE text", "Windows-style wide string (no NUL terminator)", "text",
            ["value", "role"]),
        new("quote", "Quoted string", "Wrap value in \"…\" (role applies to inner)", "text",
            ["value", "role"]),
        new("pad", "Pad / align", "Pad the next block to N bytes with 0x00 (or value)", "binary",
            ["count", "value"]),
        new("fill", "Fill range", "N bytes of a single value (0x00 / 0xFF / char)", "binary",
            ["count", "value"]),
        new("cyclic", "Cyclic pattern", "Unique pattern length N (depth triage)", "binary",
            ["count"]),
        new("len-prefix", "Length prefix", "u8/u16/u32 LE|BE of the following payload size", "binary",
            ["format"]),
    ];

    public static CasePreviewDto Preview(IReadOnlyList<CaseStepDto> steps)
    {
        var (bytes, hints, notes) = Render(steps);
        var previewLen = Math.Min(bytes.Length, 256);
        var hexPreview = ToHex(bytes.AsSpan(0, previewLen));
        if (bytes.Length > previewLen)
            hexPreview += " …";
        var ascii = ToAscii(bytes.AsSpan(0, previewLen));
        if (bytes.Length > previewLen)
            ascii += " …";
        return new CasePreviewDto(
            bytes.Length,
            hexPreview,
            ascii,
            Convert.ToHexString(bytes),
            hints,
            notes);
    }

    public static (byte[] Bytes, List<string> Hints, List<string> Notes) Render(IReadOnlyList<CaseStepDto> steps)
    {
        var parts = new List<byte[]>();
        var hints = new List<string>();
        var notes = new List<string>();
        var pendingLenFormat = (string?)null;
        var pendingPad = ((int Count, byte Fill)?)null;

        foreach (var step in steps)
        {
            var op = (step.Op ?? "").Trim().ToLowerInvariant();
            if (op is "len-prefix" or "length" or "size")
            {
                pendingLenFormat = string.IsNullOrWhiteSpace(step.Format) ? "u16le" : step.Format!;
                notes.Add($"Length prefix ({pendingLenFormat}) applies to the next block.");
                continue;
            }

            if (op is "pad" or "align")
            {
                var fill = ParsePadByte(step.Value);
                pendingPad = (Math.Clamp(step.Count ?? 16, 0, 1_000_000), fill);
                notes.Add($"Pad to {pendingPad.Value.Count} bytes applies to the next block.");
                continue;
            }

            var chunk = RenderStep(step);
            if (pendingLenFormat is not null)
            {
                parts.Add(EncodeLength(chunk.Length, pendingLenFormat));
                pendingLenFormat = null;
            }

            if (pendingPad is not null)
            {
                var (padTo, fill) = pendingPad.Value;
                if (chunk.Length < padTo)
                {
                    var padded = new byte[padTo];
                    Buffer.BlockCopy(chunk, 0, padded, 0, chunk.Length);
                    Array.Fill(padded, fill, chunk.Length, padTo - chunk.Length);
                    chunk = padded;
                }
                pendingPad = null;
            }

            parts.Add(chunk);

            var role = (step.Role ?? "fuzzable").Trim().ToLowerInvariant();
            if ((role is "fuzzable" or "string") &&
                (op is "text" or "string" or "delim" or "quote" or "utf16") &&
                !string.IsNullOrWhiteSpace(step.Value) &&
                step.Value!.Length is > 0 and < 200)
            {
                hints.Add(step.Value!);
            }
        }

        if (pendingLenFormat is not null)
            notes.Add("Warning: length-prefix had no following block.");
        if (pendingPad is not null)
            notes.Add("Warning: pad had no following block.");

        var total = parts.Sum(p => p.Length);
        var buf = new byte[total];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        if (hints.Count == 0)
            notes.Add("Tip: mark string/delim blocks as fuzzable to harvest dictionary tokens.");

        return (buf, hints.Distinct(StringComparer.Ordinal).ToList(), notes);
    }

    /// <summary>Max bytes kept in editable hex body steps (rest noted; use Save exact sample).</summary>
    public const int MaxTemplateBodyBytes = 8_192;

    /// <summary>Turn a sample file into a best-effort fuzz template (magic / length / text / binary).</summary>
    public static CaseImportBytesDto SuggestFromBytes(byte[] bytes, string? fileName = null)
    {
        var previewLen = Math.Min(bytes.Length, 64);
        var notes = new List<string>();
        if (bytes.Length == 0)
            return new CaseImportBytesDto(0, "", "", [], "empty", ["Empty sample."], SuggestSeedName(fileName, "empty"));

        var (format, magicLen) = DetectFormat(bytes, fileName);
        notes.Add($"Detected format: {format} ({bytes.Length} bytes).");

        List<CaseStepDto> steps;
        var asciiRatio = bytes.Count(b => b is >= 32 and <= 126 or 9 or 10 or 13) / (double)Math.Max(1, bytes.Length);

        if (format is "xml" or "html" or "json" or "text" || asciiRatio >= 0.85)
        {
            steps = SuggestTextTemplate(bytes, format, notes);
        }
        else
        {
            steps = SuggestBinaryTemplate(bytes, format, magicLen, notes);
        }

        if (bytes.Length > MaxTemplateBodyBytes)
            notes.Add($"Sample is larger than {MaxTemplateBodyBytes} bytes — recipe keeps the header + a body slice. Use “Save exact sample” to keep the full file as a seed.");

        notes.Add("Static blocks stay put; fuzzable hex/text is what mutators should chew. Preview, then Save as seed.");

        return new CaseImportBytesDto(
            bytes.Length,
            ToHex(bytes.AsSpan(0, previewLen)) + (bytes.Length > previewLen ? " …" : ""),
            ToAscii(bytes.AsSpan(0, previewLen)) + (bytes.Length > previewLen ? " …" : ""),
            steps,
            format,
            notes,
            SuggestSeedName(fileName, format));
    }

    public static CaseImportBytesDto Import(CaseImportBytesRequest request)
    {
        byte[] bytes;
        if (!string.IsNullOrWhiteSpace(request.Hex))
            bytes = ParseHex(request.Hex!);
        else if (!string.IsNullOrWhiteSpace(request.Base64))
        {
            var b64 = request.Base64!.Trim();
            // Allow data URLs
            var comma = b64.IndexOf("base64,", StringComparison.OrdinalIgnoreCase);
            if (comma >= 0)
                b64 = b64[(comma + "base64,".Length)..];
            bytes = Convert.FromBase64String(b64);
        }
        else if (request.Text is not null)
            bytes = Encoding.UTF8.GetBytes(Unescape(request.Text));
        else
            throw new ArgumentException("Provide hex, text, or base64");

        if (bytes.Length > 4_000_000)
            throw new ArgumentException("Sample too large (max 4 MB for template import). Trim the file or use a smaller case.");

        return SuggestFromBytes(bytes, request.FileName);
    }

    private static (string Format, int MagicLen) DetectFormat(byte[] bytes, string? fileName)
    {
        var ext = Path.GetExtension(fileName ?? "").TrimStart('.').ToLowerInvariant();
        if (bytes.Length >= 4)
        {
            // PNG
            if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47)
                return ("png", 8);
            // JPEG
            if (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF)
                return ("jpeg", 3);
            // GIF
            if (bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46)
                return ("gif", 6);
            // PDF
            if (bytes[0] == 0x25 && bytes[1] == 0x50 && bytes[2] == 0x44 && bytes[3] == 0x46)
                return ("pdf", 5);
            // ZIP / Office OOXML
            if (bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] is 0x03 or 0x05 or 0x07)
                return (ext is "docx" or "xlsx" or "pptx" ? ext : "zip", 4);
            // ELF
            if (bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46)
                return ("elf", 4);
            // PE / MZ
            if (bytes[0] == 0x4D && bytes[1] == 0x5A)
                return ("pe", 2);
            // RIFF — refine WAVE / AVI / WEBP
            if (bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46)
            {
                if (bytes.Length >= 12)
                {
                    var form = Encoding.ASCII.GetString(bytes, 8, 4);
                    if (form.Equals("WAVE", StringComparison.Ordinal))
                        return ("wav", 12);
                    if (form.Equals("AVI ", StringComparison.Ordinal))
                        return ("avi", 12);
                    if (form.Equals("WEBP", StringComparison.Ordinal))
                        return ("webp", 12);
                }
                return ("riff", 12);
            }
            // ID3 / MP3
            if (bytes[0] == 0x49 && bytes[1] == 0x44 && bytes[2] == 0x33)
                return ("mp3", 10);
            if (bytes.Length >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0)
                return ("mp3", 4);
            // FLAC
            if (bytes[0] == 0x66 && bytes[1] == 0x4C && bytes[2] == 0x61 && bytes[3] == 0x43)
                return ("flac", 4);
            // Ogg
            if (bytes[0] == 0x4F && bytes[1] == 0x67 && bytes[2] == 0x67 && bytes[3] == 0x53)
                return ("ogg", 27);
            // AIFF (FORM….AIFF)
            if (bytes[0] == 0x46 && bytes[1] == 0x4F && bytes[2] == 0x52 && bytes[3] == 0x4D &&
                bytes.Length >= 12 &&
                Encoding.ASCII.GetString(bytes, 8, 4) is "AIFF" or "AIFC")
                return ("aiff", 12);
            // BMP
            if (bytes[0] == 0x42 && bytes[1] == 0x4D)
                return ("bmp", 2);
        }

        // Extension hints for audio when magic is ambiguous
        if (ext is "wav" or "wave") return ("wav", 12);
        if (ext is "mp3" or "mpeg") return ("mp3", 0);
        if (ext is "flac") return ("flac", 4);
        if (ext is "ogg" or "oga" or "opus") return ("ogg", 4);
        if (ext is "aiff" or "aif") return ("aiff", 12);

        var head = Encoding.ASCII.GetString(bytes.AsSpan(0, Math.Min(bytes.Length, 64))).TrimStart();
        if (head.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
            head.StartsWith("<", StringComparison.Ordinal) && head.Contains('>', StringComparison.Ordinal))
            return head.Contains("html", StringComparison.OrdinalIgnoreCase) ? ("html", 0) : ("xml", 0);
        if (head.StartsWith('{') || head.StartsWith('['))
            return ("json", 0);

        // Length-prefixed lab frame: u16le / u32le matching remaining payload
        if (bytes.Length >= 3)
        {
            var u16 = bytes[0] | (bytes[1] << 8);
            if (u16 == bytes.Length - 2 && u16 is > 0 and < 1_000_000)
                return ("len16-frame", 0);
        }
        if (bytes.Length >= 5)
        {
            var u32 = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
            if (u32 == bytes.Length - 4 && u32 is > 0 and < 4_000_000)
                return ("len32-frame", 0);
        }

        // Printable magic (4–8 ASCII) then binary
        var magic = 0;
        while (magic < Math.Min(16, bytes.Length) && bytes[magic] is >= 32 and <= 126)
            magic++;
        if (magic is >= 3 and <= 12 && bytes.Length > magic + 4)
        {
            var restAscii = bytes.Skip(magic).Count(b => b is >= 32 and <= 126) / (double)(bytes.Length - magic);
            if (restAscii < 0.5)
                return ("magic-bin", magic);
        }

        if (!string.IsNullOrWhiteSpace(ext))
            return (ext, 0);

        var asciiRatio = bytes.Count(b => b is >= 32 and <= 126 or 9 or 10 or 13) / (double)bytes.Length;
        return asciiRatio >= 0.85 ? ("text", 0) : ("binary", 0);
    }

    private static List<CaseStepDto> SuggestTextTemplate(byte[] bytes, string format, List<string> notes)
    {
        var steps = new List<CaseStepDto>();
        var text = Encoding.UTF8.GetString(bytes);
        if (format is "xml" or "html")
        {
            notes.Add("XML/HTML sample — tags stay static where possible; text nodes marked fuzzable.");
            // Split on tag boundaries for a coarse editable recipe
            var parts = System.Text.RegularExpressions.Regex.Split(text, @"(<[^>]+>)");
            var n = 0;
            foreach (var part in parts)
            {
                if (string.IsNullOrEmpty(part)) continue;
                if (n++ > 40)
                {
                    notes.Add("Truncated recipe after 40 text blocks — save exact sample for the full document.");
                    break;
                }
                var isTag = part.StartsWith('<') && part.EndsWith('>');
                steps.Add(new CaseStepDto("text", part, Role: isTag ? "static" : "fuzzable"));
            }
            if (steps.Count == 0)
                steps.Add(new CaseStepDto("text", text, Role: "fuzzable"));
            return steps;
        }

        if (format == "json")
        {
            notes.Add("JSON sample — whole document as one fuzzable text block (mutate structure carefully).");
            steps.Add(new CaseStepDto("text", text.Length > MaxTemplateBodyBytes
                ? text[..MaxTemplateBodyBytes]
                : text, Role: "fuzzable"));
            return steps;
        }

        var lines = text.Split(["\r\n", "\n"], StringSplitOptions.None);
        var useCrlf = text.Contains("\r\n", StringComparison.Ordinal);
        for (var i = 0; i < lines.Length && i < 60; i++)
        {
            if (lines[i].Length > 0)
            {
                var looksStatic = lines[i] is "GET" or "POST" or "HTTP/1.0" or "HTTP/1.1" or
                                  "USER" or "PASS" or "QUIT" or "TRUN" or "GMON" or "STAT" ||
                                  lines[i].StartsWith("<?xml", StringComparison.OrdinalIgnoreCase);
                steps.Add(new CaseStepDto("text", lines[i], Role: looksStatic ? "static" : "fuzzable"));
            }
            if (i < lines.Length - 1)
                steps.Add(new CaseStepDto(useCrlf ? "crlf" : "lf"));
        }
        if (steps.Count == 0)
            steps.Add(new CaseStepDto("text", text, Role: "fuzzable"));
        return steps;
    }

    private static List<CaseStepDto> SuggestBinaryTemplate(
        byte[] bytes,
        string format,
        int magicLen,
        List<string> notes)
    {
        var steps = new List<CaseStepDto>();

        if (format is "len16-frame")
        {
            notes.Add("Looks like a u16le length-prefixed frame — template uses len-prefix + fuzzable body.");
            steps.Add(new CaseStepDto("len-prefix", Format: "u16le"));
            var body = bytes.AsSpan(2);
            AddHexBody(steps, body, fuzzable: true);
            return steps;
        }

        if (format is "len32-frame")
        {
            notes.Add("Looks like a u32le length-prefixed frame — template uses len-prefix + fuzzable body.");
            steps.Add(new CaseStepDto("len-prefix", Format: "u32le"));
            var body = bytes.AsSpan(4);
            AddHexBody(steps, body, fuzzable: true);
            return steps;
        }

        if (format is "wav")
            return SuggestWavTemplate(bytes, notes);

        if (format is "mp3")
            return SuggestMp3Template(bytes, magicLen, notes);

        if (format is "flac")
        {
            notes.Add("FLAC — keep fLaC magic static; STREAMINFO/body fuzzable.");
            var mag = Math.Min(4, bytes.Length);
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, mag)), Role: "static"));
            if (bytes.Length > mag)
                AddHexBody(steps, bytes.AsSpan(mag), fuzzable: true);
            return steps;
        }

        if (format is "ogg")
        {
            notes.Add("Ogg — keep OggS page capture pattern static; segments/payload fuzzable.");
            var mag = Math.Min(Math.Max(magicLen, 4), Math.Min(27, bytes.Length));
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, mag)), Role: "static"));
            if (bytes.Length > mag)
                AddHexBody(steps, bytes.AsSpan(mag), fuzzable: true);
            return steps;
        }

        if (bytes.Length >= 12 && format is "riff" or "avi" or "webp" or "aiff")
        {
            notes.Add($"{format.ToUpperInvariant()} container — keep magic + form type static; size + chunks fuzzable.");
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, 4)), Role: "static"));
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(4, 4)), Role: "fuzzable"));
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(8, 4)), Role: "static"));
            AddHexBody(steps, bytes.AsSpan(12), fuzzable: true);
            return steps;
        }

        if (magicLen > 0)
        {
            notes.Add($"Keeping {magicLen}-byte magic/header static; body marked fuzzable.");
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, magicLen)), Role: "static"));
            // After magic, try length field
            var rest = bytes.AsSpan(magicLen);
            if (rest.Length >= 2)
            {
                var u16 = rest[0] | (rest[1] << 8);
                if (u16 == rest.Length - 2 && u16 > 0)
                {
                    notes.Add("Found u16le length after magic.");
                    steps.Add(new CaseStepDto("len-prefix", Format: "u16le"));
                    AddHexBody(steps, rest[2..], fuzzable: true);
                    return steps;
                }
            }
            if (rest.Length >= 4)
            {
                var u32 = rest[0] | (rest[1] << 8) | (rest[2] << 16) | (rest[3] << 24);
                if (u32 == rest.Length - 4 && u32 > 0)
                {
                    notes.Add("Found u32le length after magic.");
                    steps.Add(new CaseStepDto("len-prefix", Format: "u32le"));
                    AddHexBody(steps, rest[4..], fuzzable: true);
                    return steps;
                }
            }
            AddHexBody(steps, rest, fuzzable: true);
            return steps;
        }

        // Generic binary: short static header guess + fuzzable body
        var header = Math.Min(8, bytes.Length);
        if (bytes.Length > 16)
        {
            notes.Add("Generic binary — first 8 bytes static (tweak if wrong), remainder fuzzable.");
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, header)), Role: "static"));
            AddHexBody(steps, bytes.AsSpan(header), fuzzable: true);
        }
        else
        {
            AddHexBody(steps, bytes, fuzzable: true);
        }
        return steps;
    }

    private static List<CaseStepDto> SuggestWavTemplate(byte[] bytes, List<string> notes)
    {
        var steps = new List<CaseStepDto>();
        notes.Add("WAV (RIFF/WAVE) — header + fmt chunk stay structured; data payload is fuzzable.");
        if (bytes.Length < 12)
        {
            AddHexBody(steps, bytes, fuzzable: true);
            return steps;
        }

        steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, 4)), Role: "static")); // RIFF
        steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(4, 4)), Role: "fuzzable")); // file size
        steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(8, 4)), Role: "static")); // WAVE

        var i = 12;
        while (i + 8 <= bytes.Length && steps.Count < 24)
        {
            var id = Encoding.ASCII.GetString(bytes, i, 4);
            var size = BitConverter.ToInt32(bytes, i + 4);
            if (size < 0 || i + 8 + size > bytes.Length)
            {
                AddHexBody(steps, bytes.AsSpan(i), fuzzable: true);
                break;
            }

            if (id is "fmt ")
            {
                notes.Add("fmt chunk kept mostly static (sample rate / channels).");
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i, 8 + size)), Role: "static"));
            }
            else if (id is "data")
            {
                notes.Add("data chunk — size field fuzzable; PCM/samples fuzzable.");
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i, 4)), Role: "static")); // "data"
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i + 4, 4)), Role: "fuzzable")); // size
                AddHexBody(steps, bytes.AsSpan(i + 8, size), fuzzable: true);
                i += 8 + size + (size & 1); // word align
                // remainder after data
                if (i < bytes.Length)
                    AddHexBody(steps, bytes.AsSpan(i), fuzzable: true);
                return steps;
            }
            else
            {
                // LIST/fact/other — keep id static, body fuzzable
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i, 4)), Role: "static"));
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i + 4, 4)), Role: "fuzzable"));
                AddHexBody(steps, bytes.AsSpan(i + 8, Math.Min(size, MaxTemplateBodyBytes)), fuzzable: true);
            }

            i += 8 + size + (size & 1);
        }

        if (i < bytes.Length && steps.Count < 24)
            AddHexBody(steps, bytes.AsSpan(i), fuzzable: true);
        return steps;
    }

    private static List<CaseStepDto> SuggestMp3Template(byte[] bytes, int magicLen, List<string> notes)
    {
        var steps = new List<CaseStepDto>();
        notes.Add("MP3 — keep ID3/frame sync header static; audio frames fuzzable.");
        var header = magicLen > 0 ? Math.Min(magicLen, bytes.Length) : Math.Min(4, bytes.Length);
        if (bytes.Length >= 10 && bytes[0] == 0x49 && bytes[1] == 0x44 && bytes[2] == 0x33)
        {
            // ID3v2 size is synchsafe in bytes 6..9
            var id3Len = ((bytes[6] & 0x7F) << 21) | ((bytes[7] & 0x7F) << 14)
                         | ((bytes[8] & 0x7F) << 7) | (bytes[9] & 0x7F);
            header = Math.Min(bytes.Length, 10 + id3Len);
            notes.Add($"ID3v2 tag ~{header} bytes kept as header block.");
        }
        steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(0, header)), Role: "static"));
        if (bytes.Length > header)
            AddHexBody(steps, bytes.AsSpan(header), fuzzable: true);
        return steps;
    }

    private static void AddHexBody(List<CaseStepDto> steps, ReadOnlySpan<byte> body, bool fuzzable)
    {
        if (body.Length == 0)
            return;
        var take = Math.Min(body.Length, MaxTemplateBodyBytes);
        // One fuzzable block is easier to mutate than dozens of 32-byte chips
        if (take <= 256 || fuzzable)
        {
            steps.Add(new CaseStepDto(
                "hex",
                Convert.ToHexString(body[..take]),
                Role: fuzzable ? "fuzzable" : "static"));
            return;
        }
        for (var i = 0; i < take; i += 32)
        {
            var n = Math.Min(32, take - i);
            steps.Add(new CaseStepDto("hex", Convert.ToHexString(body.Slice(i, n)), Role: "fuzzable"));
        }
    }

    private static string SuggestSeedName(string? fileName, string format)
    {
        if (!string.IsNullOrWhiteSpace(fileName))
        {
            var safe = Path.GetFileName(fileName);
            if (!string.IsNullOrWhiteSpace(safe))
                return safe;
        }
        var ext = format switch
        {
            "xml" or "html" => ".xml",
            "json" => ".json",
            "png" => ".png",
            "jpeg" => ".jpg",
            "gif" => ".gif",
            "pdf" => ".pdf",
            "zip" or "docx" or "xlsx" or "pptx" => $".{format}",
            "wav" or "riff" => ".wav",
            "mp3" => ".mp3",
            "flac" => ".flac",
            "ogg" => ".ogg",
            "avi" => ".avi",
            "webp" => ".webp",
            "aiff" => ".aiff",
            "text" => ".txt",
            _ => ".bin",
        };
        return $"sample_from_upload{ext}";
    }

    private static byte[] RenderStep(CaseStepDto step)
    {
        var op = (step.Op ?? "").Trim().ToLowerInvariant();
        return op switch
        {
            "static" or "text" or "string" or "delim" or "delimiter" =>
                Encoding.UTF8.GetBytes(Unescape(step.Value ?? "")),
            "quote" or "quoted" =>
                Encoding.UTF8.GetBytes("\"" + Unescape(step.Value ?? "") + "\""),
            "utf16" or "utf16le" or "wide" =>
                Encoding.Unicode.GetBytes(Unescape(step.Value ?? "")),
            "hex" or "bytes" => ParseHex(step.Value ?? ""),
            "repeat" => Repeat(step.Value ?? "A", step.Count ?? 100),
            "fill" => Repeat(step.Value ?? "0x00", step.Count ?? 16),
            "random" => RandomBytes(Math.Clamp(step.Count ?? 16, 0, 1_000_000)),
            "interesting" or "int" => Interesting(step.Format ?? "u32le", step.Value),
            "null" or "zero" => [0],
            "crlf" or "newline" => "\r\n"u8.ToArray(),
            "lf" => "\n"u8.ToArray(),
            "base64" or "b64" => Convert.FromBase64String((step.Value ?? "").Trim()),
            "cyclic" or "pattern" => Cyclic(Math.Clamp(step.Count ?? 100, 1, 1_000_000)),
            _ => throw new ArgumentException($"Unknown case op: {step.Op}"),
        };
    }

    private static byte ParsePadByte(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            byte.TryParse(value.AsSpan(2), NumberStyles.HexNumber, null, out var b))
            return b;
        return (byte)value[0];
    }

    private static string Unescape(string s) =>
        s.Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal)
            .Replace("\\0", "\0", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal);

    private static byte[] ParseHex(string value)
    {
        var hex = value.Replace(" ", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        if (hex.Length % 2 != 0)
            hex = "0" + hex;
        return Convert.FromHexString(hex);
    }

    private static byte[] Repeat(string value, int count)
    {
        count = Math.Clamp(count, 0, 1_000_000);
        byte unit;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            byte.TryParse(value.AsSpan(2), NumberStyles.HexNumber, null, out var b))
            unit = b;
        else if (value.Length == 0)
            unit = (byte)'A';
        else
            unit = (byte)value[0];

        var buf = new byte[count];
        Array.Fill(buf, unit);
        return buf;
    }

    private static byte[] RandomBytes(int count)
    {
        var buf = new byte[count];
        Random.Shared.NextBytes(buf);
        return buf;
    }

    private static readonly long[] InterestingValues =
    [
        0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
        0x7fffffff, unchecked((int)0x80000000), unchecked((uint)0xffffffff),
        -1, -128, 127, 255, 1024, 4096, 65535,
    ];

    private static byte[] Interesting(string format, string? value)
    {
        long n;
        if (!string.IsNullOrWhiteSpace(value) &&
            (long.TryParse(value, out n) ||
             long.TryParse(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value,
                 NumberStyles.HexNumber, null, out n)))
        {
            /* use parsed */
        }
        else
        {
            n = InterestingValues[Random.Shared.Next(InterestingValues.Length)];
        }

        format = format.Trim().ToLowerInvariant();
        return format switch
        {
            "u8" or "byte" => [(byte)n],
            "u16be" or "be16" => [(byte)(n >> 8), (byte)n],
            "u16le" or "le16" => [(byte)n, (byte)(n >> 8)],
            "u32be" or "be32" => [(byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n],
            _ => [(byte)n, (byte)(n >> 8), (byte)(n >> 16), (byte)(n >> 24)], // u32le
        };
    }

    private static byte[] EncodeLength(int length, string format) =>
        format.Trim().ToLowerInvariant() switch
        {
            "u8" => [(byte)length],
            "u16be" => [(byte)(length >> 8), (byte)length],
            "u16le" => [(byte)length, (byte)(length >> 8)],
            "u32be" => [(byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length],
            "u32le" => [(byte)length, (byte)(length >> 8), (byte)(length >> 16), (byte)(length >> 24)],
            _ => [(byte)length, (byte)(length >> 8)],
        };

    /// <summary>Simple unique alphabetic cycle (depth triage — not exploit tooling).</summary>
    private static byte[] Cyclic(int length)
    {
        var buf = new byte[length];
        for (var i = 0; i < length; i++)
        {
            var a = i / (26 * 26) % 26;
            var b = i / 26 % 26;
            var c = i % 26;
            // 3-char alphabet pattern: Aa0 style simplified to letters
            buf[i] = (byte)('A' + (a + b + c) % 26);
            if (i % 3 == 1) buf[i] = (byte)('a' + b);
            if (i % 3 == 2) buf[i] = (byte)('0' + c % 10);
        }
        return buf;
    }

    private static string ToHex(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length * 3);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(bytes[i].ToString("X2"));
        }
        return sb.ToString();
    }

    private static string ToAscii(ReadOnlySpan<byte> bytes)
    {
        var chars = new char[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            chars[i] = b is >= 32 and <= 126 ? (char)b : '.';
        }
        return new string(chars);
    }

    /// <summary>
    /// Map Scare Floor blocks → ProtocolDefinition (Sulley/boofuzz YAML models).
    /// Hex/binary ops emit companion seed files listed in <paramref name="seedFiles"/>.
    /// </summary>
    public static ProtocolDefinition StepsToProtocol(
        string name,
        string? description,
        IReadOnlyList<CaseStepDto> steps,
        out List<(string RelativeSeed, byte[] Bytes)> seedFiles)
    {
        seedFiles = [];
        var blocks = new List<ProtocolBlockDefinition>();
        var i = 0;
        foreach (var s in steps ?? [])
        {
            i++;
            var op = (s.Op ?? "").Trim().ToLowerInvariant();
            var mutable = !string.Equals(s.Role, "static", StringComparison.OrdinalIgnoreCase);
            switch (op)
            {
                case "static":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "static",
                        Name = $"s{i}",
                        Value = s.Value ?? "",
                        Mutable = false,
                    });
                    break;
                case "crlf":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "static",
                        Name = $"crlf{i}",
                        Value = "\r\n",
                        Mutable = false,
                    });
                    break;
                case "lf":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "static",
                        Name = $"lf{i}",
                        Value = "\n",
                        Mutable = false,
                    });
                    break;
                case "null":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "static",
                        Name = $"nul{i}",
                        Value = "\0",
                        Mutable = false,
                    });
                    break;
                case "delim":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "delim",
                        Name = $"d{i}",
                        Value = string.IsNullOrEmpty(s.Value) ? " " : s.Value,
                        Mutable = mutable,
                    });
                    break;
                case "text":
                case "string":
                case "quote":
                case "utf16":
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "string",
                        Name = string.IsNullOrWhiteSpace(s.Value) ? $"f{i}" : SanitizeFieldName(s.Value!, i),
                        Value = s.Value ?? "",
                        Mutable = mutable,
                        MaxSize = 4096,
                    });
                    break;
                case "hex":
                case "random":
                case "repeat":
                case "fill":
                case "cyclic":
                case "interesting":
                case "base64":
                {
                    var (bytes, _, _) = Render([s]);
                    var seedRel = $"seeds/proto_{SanitizeFieldName(name, 0)}_{i}.bin";
                    seedFiles.Add((seedRel, bytes));
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "bytes",
                        Name = $"b{i}",
                        Mutable = mutable,
                        MinSize = 1,
                        MaxSize = Math.Max(4096, bytes.Length * 4),
                        SeedFile = seedRel,
                    });
                    break;
                }
                case "len-prefix":
                    // Alone — keep as dword size field; paired promote is best-effort later
                    blocks.Add(new ProtocolBlockDefinition
                    {
                        Type = "dword",
                        Name = $"len{i}",
                        Value = "0",
                        Mutable = true,
                        LittleEndian = !(s.Format?.Contains("be", StringComparison.OrdinalIgnoreCase) ?? false),
                    });
                    break;
                default:
                    if (!string.IsNullOrEmpty(s.Value))
                    {
                        blocks.Add(new ProtocolBlockDefinition
                        {
                            Type = "string",
                            Name = $"x{i}",
                            Value = s.Value,
                            Mutable = mutable,
                        });
                    }
                    break;
            }
        }

        return new ProtocolDefinition
        {
            Name = name,
            Description = description ?? $"Promoted from Scare Floor ({steps?.Count ?? 0} blocks)",
            Blocks = blocks,
        };
    }

    private static string SanitizeFieldName(string raw, int i)
    {
        var s = Regex.Replace(raw.Trim().ToLowerInvariant(), @"[^a-z0-9_\-]+", "_");
        s = s.Trim('_');
        if (string.IsNullOrEmpty(s) || s.Length > 24)
            return $"f{i}";
        return s;
    }
}
