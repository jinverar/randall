using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Stack Lens — map crash input onto a stack window and label CONTROL slots.
/// Lab-only; cites offsets/roles — no payloads.
/// </summary>
public static class StackLens
{
    private const uint Memory64ListStream = 9;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public static StackLensReportDto AnalyzeCrash(
        Guid crashId,
        int windowBytes = 128,
        string? exeOverride = null,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
        {
            return new StackLensReportDto(
                crashId, "", "unknown", null, null, windowBytes, 8, [], null, [],
                "stack-lens: crash not found", "none", Error: "crash not found");
        }

        windowBytes = Math.Clamp(windowBytes, 16, 512);
        byte[]? input = null;
        try
        {
            if (File.Exists(detail.Summary.InputPath))
                input = File.ReadAllBytes(detail.Summary.InputPath);
        }
        catch { /* ignore */ }

        var dump = detail.Summary.MiniDumpPath ?? detail.Analysis?.DumpPath ?? detail.Sidecar?.MiniDumpPath;
        var modules = RopStudio.ResolveCrashModules(detail, repoRoot, exeOverride, maxModules: 3);
        var exe = modules.FirstOrDefault() ?? exeOverride;
        var arch = GuessArch(detail, exe);
        var wordSize = arch == "x86" ? 4 : 8;
        var spReg = arch == "x86" ? "ESP" : "RSP";
        var spValue = detail.Analysis?.Registers?.Rsp ?? detail.Triage?.Rsp;
        var hints = new List<string>
        {
            "Stack Lens cites CONTROL slots — no shellcode / payloads",
            "docs/WINDBG_FUZZ_PKG.md",
        };

        string? guideReg = null;
        int? guideOff = null;
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        var guidePath = Path.Combine(crashesDir, $"{crashId:N}_exploit_guide.json");
        LoadGuideControl(guidePath, ref guideReg, ref guideOff);

        var words = new List<StackLensWordDto>();
        var source = "none";

        // 1) Linux core via gdb
        if (!string.IsNullOrWhiteSpace(dump) && File.Exists(dump) &&
            !string.IsNullOrWhiteSpace(exe) && File.Exists(exe) &&
            LooksLikeElfCore(dump, exe))
        {
            var spExpr = arch == "x86" ? "$esp" : "$rsp";
            var fmt = arch == "x86" ? "wx" : "gx";
            var count = Math.Max(4, windowBytes / wordSize);
            var raw = ExploitDevTools.CoreStackWords(exe, dump, count, spExpr, fmt);
            if (raw.Count > 0)
            {
                source = "gdb-core";
                TryParseUlong(spValue, out var spBase);
                for (var i = 0; i < raw.Count; i++)
                {
                    var off = i * wordSize;
                    var addr = spBase != 0 ? $"0x{spBase + (ulong)off:X}" : $"SP+0x{off:X}";
                    words.Add(ClassifyWord(off, addr, raw[i], wordSize, input, detail, guideOff));
                }
            }
            else
            {
                hints.Add("gdb stack window empty — install gdb or check core/exe match");
            }
        }

        // 2) Windows minidump Memory64 around RSP
        if (words.Count == 0 && OperatingSystem.IsWindows() &&
            !string.IsNullOrWhiteSpace(dump) && File.Exists(dump) &&
            TryParseUlong(spValue, out var rsp) && rsp != 0)
        {
            var slice = TryReadMinidumpWindow(dump, rsp, windowBytes);
            if (slice is { Length: > 0 })
            {
                source = "minidump";
                for (var i = 0; i + wordSize <= slice.Length; i += wordSize)
                {
                    var val = wordSize == 4
                        ? $"0x{BitConverter.ToUInt32(slice, i):X}"
                        : $"0x{BitConverter.ToUInt64(slice, i):X}";
                    words.Add(ClassifyWord(i, $"0x{rsp + (ulong)i:X}", val, wordSize, input, detail, guideOff));
                }
            }
            else
            {
                hints.Add("RSP not in Memory64 ranges (light/truncated dump) — open WinDbg and run !rf.stack");
            }
        }

        // 3) Registers-only CONTROL map
        if (words.Count == 0)
        {
            source = "registers-only";
            hints.Add("No stack memory window — classifying registers / guide CONTROL only");
            if (detail.Analysis?.Registers is { } regs)
            {
                AddReg(words, "RIP", regs.Rip, input);
                AddReg(words, "RSP", regs.Rsp, input);
                AddReg(words, "RBP", regs.Rbp, input);
                AddReg(words, "RAX", regs.Rax, input);
                AddReg(words, "RBX", regs.Rbx, input);
                AddReg(words, "RCX", regs.Rcx, input);
                AddReg(words, "RDX", regs.Rdx, input);
            }

            if (guideOff is int goff)
            {
                words.Insert(0, new StackLensWordDto(
                    0, guideReg ?? "CONTROL", "from-guide", "controlled", goff,
                    Note: "from *_exploit_guide.json"));
            }
        }

        AnnotateRoles(words, detail, wordSize);

        var primary = PickPrimary(words, guideReg, guideOff, spReg);
        if (primary is null && guideOff is int g)
            primary = new StackLensPrimaryControlDto(guideReg ?? "CONTROL", "from-guide", g, "controlled");

        var controlled = words.Count(w =>
            w.InputOffset is not null && w.Role is "controlled" or "return-slot");
        var summary = primary is { InputOffset: int po }
            ? $"stack-lens: CONTROL {primary.Where} @ {po} · {words.Count} slot(s) · {source}"
            : controlled > 0
                ? $"stack-lens: {controlled} controlled slot(s) · {words.Count} word(s) · {source}"
                : $"stack-lens: {words.Count} word(s) · no CONTROL match · {source}";

        Directory.CreateDirectory(crashesDir);
        var outPath = Path.Combine(crashesDir, $"{crashId:N}_stack_lens.json");
        var report = new StackLensReportDto(
            crashId,
            detail.Summary.Project,
            arch,
            spReg,
            spValue,
            windowBytes,
            wordSize,
            words,
            primary,
            hints,
            summary,
            source,
            outPath.Replace('\\', '/'),
            Error: words.Count == 0 && primary is null ? "no stack/register window" : null,
            DumpPath: dump?.Replace('\\', '/'),
            ExePath: exe?.Replace('\\', '/'));

        try
        {
            File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonOpts));
        }
        catch (Exception ex)
        {
            return report with { Error = ex.Message, OutputPath = null };
        }

        return report;
    }

    public static StackLensReportDto? TryRead(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null) return null;
        var path = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project, $"{crashId:N}_stack_lens.json");
        if (!File.Exists(path)) return null;
        try
        {
            return JsonSerializer.Deserialize<StackLensReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Classify a single stack/register word (tests + host).</summary>
    public static StackLensWordDto ClassifyWord(
        int offsetFromSp,
        string addressHex,
        string valueHex,
        int wordSize,
        byte[]? input,
        CrashDetailDto? detail = null,
        int? guideOffset = null)
    {
        // Only label controlled when the word's bytes appear in the crashing input
        // (or a detected cyclic run). Never invent CONTROL from guide alone on SP+0.
        _ = guideOffset;
        var inputOff = MatchInput(valueHex, input);

        var role = inputOff is not null ? "controlled" : "unknown";
        string? note = null;
        string? sym = null;

        if (TryParseUlong(valueHex, out var val))
        {
            if (detail?.Analysis?.Registers?.Rbp is { } rbp &&
                TryParseUlong(rbp, out var rbpVal) && rbpVal == val && val != 0)
            {
                role = inputOff is not null ? "controlled" : "frame-ptr";
                note = "matches RBP/EBP";
            }
            else if (LooksLikeCodePointer(val, out sym))
            {
                if (inputOff is not null)
                {
                    role = "return-slot";
                    note = "controlled value looks like code pointer";
                }
                else if (offsetFromSp >= 0 && offsetFromSp <= wordSize * 4)
                {
                    role = "return-slot";
                    note = "near-SP code pointer (saved RET candidate)";
                }
            }
            else if (inputOff is null && LooksCanarySuspect(val, wordSize))
            {
                role = "canary-suspect";
                note = "high-entropy / truncated word — possible stack cookie";
            }
        }

        return new StackLensWordDto(offsetFromSp, addressHex, valueHex, role, inputOff, sym, note);
    }

    /// <summary>
    /// Match a register/stack word against the crashing input.
    /// Prefer exact bytes in the input; only use cyclic Offset when the input itself
    /// looks like a Metasploit-style pattern (avoids false CONTROL on random printable qwords).
    /// </summary>
    public static int? MatchInput(string valueHex, byte[]? input)
    {
        if (string.IsNullOrWhiteSpace(valueHex))
            return null;
        if (input is not { Length: > 0 })
            return null;

        var inBuf = PatternTools.OffsetInBuffer(valueHex, input);
        if (inBuf >= 0) return inBuf;

        var inferred = PatternTools.TryInferPatternLength(input);
        if (inferred is int pl)
        {
            var cyclic = PatternTools.Offset(valueHex, Math.Max(pl, 8));
            if (cyclic >= 0) return cyclic;
        }

        return null;
    }

    private static void AddReg(List<StackLensWordDto> words, string name, string? hex, byte[]? input)
    {
        if (string.IsNullOrWhiteSpace(hex)) return;
        var off = MatchInput(hex, input);
        var role = off is not null ? "controlled" : "unknown";
        words.Add(new StackLensWordDto(-1, name, hex, role, off, Note: "register (no stack window)"));
    }

    private static void AnnotateRoles(List<StackLensWordDto> words, CrashDetailDto detail, int wordSize)
    {
        for (var i = 0; i < words.Count; i++)
        {
            var w = words[i];
            if (w.Role is not ("unknown" or "controlled")) continue;
            if (!TryParseUlong(w.ValueHex, out var val)) continue;
            if (!LooksLikeCodePointer(val, out var sym)) continue;
            if (w.InputOffset is not null)
                words[i] = w with { Role = "return-slot", SymbolHint = sym ?? w.SymbolHint, Note = w.Note ?? "controlled RET candidate" };
            else if (w.OffsetFromSp >= 0 && w.OffsetFromSp <= wordSize * 2)
                words[i] = w with { Role = "return-slot", SymbolHint = sym ?? w.SymbolHint, Note = w.Note ?? "near-SP code pointer" };
        }
    }

    private static StackLensPrimaryControlDto? PickPrimary(
        IReadOnlyList<StackLensWordDto> words,
        string? guideReg,
        int? guideOff,
        string spReg)
    {
        StackLensWordDto? Best(Func<StackLensWordDto, bool> pred) =>
            words.Where(pred).OrderBy(w => w.OffsetFromSp < 0 ? int.MaxValue : w.OffsetFromSp).FirstOrDefault();

        var hit = Best(w => w.Role == "return-slot" && w.InputOffset is not null)
                  ?? Best(w => w.Role == "controlled" && w.OffsetFromSp >= 0)
                  ?? Best(w => w.Role == "controlled");
        if (hit is not null)
        {
            var where = hit.OffsetFromSp >= 0
                ? $"{spReg}+0x{hit.OffsetFromSp:X}"
                : hit.AddressHex;
            return new StackLensPrimaryControlDto(where, hit.ValueHex, hit.InputOffset, hit.Role);
        }

        if (guideOff is int g)
            return new StackLensPrimaryControlDto(guideReg ?? "CONTROL", "from-guide", g, "controlled");
        return null;
    }

    private static bool LooksLikeCodePointer(ulong val, out string? symbol)
    {
        symbol = null;
        if (val < 0x10000) return false;
        if (IsMostlyPrintablePattern(val)) return false;

        if (val >= 0x00007FF000000000UL && val <= 0x00007FFFFFFFFFFFUL)
        {
            symbol = "user-module?";
            return true;
        }
        if (val >= 0x00400000UL && val <= 0x7FFFFFFFUL && (val & 0xFFF) < 0xE00)
        {
            symbol = "low-image?";
            return true;
        }
        return false;
    }

    private static bool LooksCanarySuspect(ulong val, int wordSize)
    {
        if (val == 0) return false;
        if (IsMostlyPrintablePattern(val)) return false;
        if (wordSize == 8 && (val & 0xFF) == 0 && val > 0xFFFFFF)
            return true;
        var bits = 0;
        for (var v = val; v != 0; v >>= 1) bits += (int)(v & 1);
        return bits is >= 20 and <= 44;
    }

    private static bool IsMostlyPrintablePattern(ulong val)
    {
        var bytes = BitConverter.GetBytes(val);
        var printable = 0;
        foreach (var b in bytes)
            if (b is >= 0x20 and <= 0x7e) printable++;
        return printable >= 4;
    }

    private static string GuessArch(CrashDetailDto detail, string? exe)
    {
        if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe))
        {
            try
            {
                Span<byte> hdr = stackalloc byte[5];
                using var fs = File.OpenRead(exe);
                if (fs.Read(hdr) >= 5)
                {
                    if (hdr[0] == 0x7F && hdr[1] == (byte)'E')
                        return hdr[4] == 1 ? "x86" : "x64";
                    if (hdr[0] == 0x4D && hdr[1] == 0x5A)
                    {
                        // PE: peek machine at e_lfanew — best-effort
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        Span<byte> peOffBuf = stackalloc byte[4];
                        if (fs.Read(peOffBuf) == 4)
                        {
                            var peOff = BitConverter.ToInt32(peOffBuf);
                            fs.Seek(peOff + 4, SeekOrigin.Begin);
                            Span<byte> mach = stackalloc byte[2];
                            if (fs.Read(mach) == 2)
                            {
                                var m = BitConverter.ToUInt16(mach);
                                if (m == 0x14C) return "x86";
                                if (m is 0x8664 or 0xAA64) return "x64";
                            }
                        }
                    }
                }
            }
            catch { /* ignore */ }
        }

        var rip = detail.Analysis?.Registers?.Rip;
        if (rip is not null && TryParseUlong(rip, out var v) && v > uint.MaxValue)
            return "x64";
        return "x64";
    }

    private static bool LooksLikeElfCore(string dump, string exe)
    {
        _ = exe;
        var ext = Path.GetExtension(dump);
        if (ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase)) return false;
        if (ext.Equals(".core", StringComparison.OrdinalIgnoreCase)) return true;
        if (Path.GetFileName(dump).Contains("core", StringComparison.OrdinalIgnoreCase)) return true;
        // Inspect the dump itself — ELF cores start with 0x7F ELF (do not infer from exe alone).
        try
        {
            Span<byte> hdr = stackalloc byte[4];
            using var fs = File.OpenRead(dump);
            if (fs.Read(hdr) >= 4 &&
                hdr[0] == 0x7F && hdr[1] == (byte)'E' && hdr[2] == (byte)'L' && hdr[3] == (byte)'F')
                return true;
        }
        catch { /* ignore */ }
        return false;
    }

    private static void LoadGuideControl(string guidePath, ref string? guideReg, ref int? guideOff)
    {
        if (!File.Exists(guidePath)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(guidePath));
            var root = doc.RootElement;
            if (TryGetString(root, "controlledRegister", out var r) ||
                TryGetString(root, "ControlledRegister", out r))
                guideReg = r;
            if (TryGetInt(root, "controlledOffset", out var o) ||
                TryGetInt(root, "ControlledOffset", out o))
                guideOff = o;
        }
        catch { /* ignore */ }
    }

    private static byte[]? TryReadMinidumpWindow(string dumpPath, ulong va, int windowBytes)
    {
        try
        {
            var dump = File.ReadAllBytes(dumpPath);
            var handle = GCHandle.Alloc(dump, GCHandleType.Pinned);
            try
            {
                var basePtr = handle.AddrOfPinnedObject();
                if (!MiniDumpReadDumpStream(basePtr, Memory64ListStream, out _, out var streamPtr, out var streamSize) ||
                    streamPtr == IntPtr.Zero || streamSize < 16)
                    return null;

                var numberOfRanges = (ulong)Marshal.ReadInt64(streamPtr, 0);
                var baseRva = (ulong)Marshal.ReadInt64(streamPtr, 8);
                if (numberOfRanges == 0 || numberOfRanges > 1_000_000)
                    return null;

                const int descSize = 16;
                const int header = 16;
                ulong cursorRva = baseRva;
                for (ulong i = 0; i < numberOfRanges; i++)
                {
                    var descOff = header + (int)(i * (ulong)descSize);
                    if (descOff + descSize > streamSize) break;
                    var start = (ulong)Marshal.ReadInt64(streamPtr, descOff);
                    var size = (ulong)Marshal.ReadInt64(streamPtr, descOff + 8);
                    if (size == 0 || size > int.MaxValue)
                    {
                        cursorRva += size;
                        continue;
                    }

                    if (va >= start && va < start + size)
                    {
                        var offsetInRange = va - start;
                        var take = (int)Math.Min((ulong)windowBytes, size - offsetInRange);
                        var fileOff = (long)(cursorRva + offsetInRange);
                        if (fileOff < 0 || fileOff + take > dump.Length || take <= 0)
                            return null;
                        return dump.AsSpan((int)fileOff, take).ToArray();
                    }

                    cursorRva += size;
                }
            }
            finally
            {
                handle.Free();
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static bool TryParseUlong(string? hex, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(hex)) return false;
        hex = hex.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        return ulong.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryGetString(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.String)
            return false;
        value = p.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryGetInt(JsonElement root, string name, out int value)
    {
        value = 0;
        if (!root.TryGetProperty(name, out var p)) return false;
        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out value)) return true;
        if (p.ValueKind == JsonValueKind.String && int.TryParse(p.GetString(), out value)) return true;
        return false;
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpReadDumpStream(
        IntPtr BaseOfDump, uint StreamNumber, out IntPtr dir, out IntPtr streamPointer, out uint streamSize);
}
