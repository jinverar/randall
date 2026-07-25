using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Headless CDB "Scream Investigator" — turns a minidump into structured
/// <see cref="DebuggerObservation"/> for Brain / Scream / canister UI.
/// Runs post-mortem only (does not fight Scream's live debug attach).
/// </summary>
public static partial class ScreamInvestigator
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string ObservationPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_debugger_observation.json");

    public static DebuggerObservation? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<DebuggerObservation>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Run expanded CDB probes on <paramref name="dumpPath"/> and persist observation sidecar.
    /// Reuses analyze/exploitable text already written by <see cref="WindowsCdbCrashAnalysisWriter"/> when present.
    /// </summary>
    public static DebuggerObservation Investigate(
        string crashesDir,
        Guid crashId,
        string dumpPath,
        CrashSidecarDto? sidecar = null,
        bool runExploitable = true,
        int timeoutMs = 120_000)
    {
        Directory.CreateDirectory(crashesDir);
        var obsPath = ObservationPathFor(crashesDir, crashId);

        if (!WindowsCdbCrashAnalysisWriter.LooksLikeWindowsDump(dumpPath)
            || !CrashDumpPaths.IsUsableDump(dumpPath))
        {
            var bad = Empty(
                dumpPath, obsPath,
                "dump missing, empty, or not a Windows minidump — Scream Investigator skipped");
            Write(obsPath, bad);
            return bad;
        }

        var cdb = DebuggerTools.FindCdb();
        if (cdb is null)
        {
            // Fall back to parsing any prior !analyze text from a previous triage pass.
            var priorAnalyze = WindowsCdbCrashAnalysisWriter.AnalyzeTextPathFor(crashesDir, crashId);
            if (File.Exists(priorAnalyze))
            {
                var fromText = BuildFromBlocks(
                    dumpPath, obsPath,
                    analyze:                 File.ReadAllText(priorAnalyze),
                    exr: "", regs: "", stack: "", disasm: "", mem: "",
                    exploitable: ReadOptional(WindowsCdbCrashAnalysisWriter.ExploitableTextPathFor(crashesDir, crashId)) ?? "",
                    timedOut: false,
                    sidecar,
                    error: "cdb not found — observation built from saved !analyze text only");
                Write(obsPath, fromText);
                return fromText;
            }

            var noCdb = Empty(dumpPath, obsPath,
                "cdb not found — install Debugging Tools (scripts/install-debuggers.ps1)");
            Write(obsPath, noCdb);
            return noCdb;
        }

        var msec = runExploitable ? DebuggerTools.FindMsecDll() : null;
        var script = WindowsCdbCrashAnalysisWriter.BuildScript(msec);
        string text;
        bool timedOut;
        try
        {
            (text, timedOut) = WindowsCdbCrashAnalysisWriter.RunCdb(cdb, dumpPath, script, timeoutMs);
        }
        catch (Exception ex)
        {
            var fail = Empty(dumpPath, obsPath, ex.Message);
            Write(obsPath, fail);
            return fail;
        }

        var analyze = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_ANALYZE_BEGIN", "RANDFUZZ_ANALYZE_END");
        var exr = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_EXR_BEGIN", "RANDFUZZ_EXR_END");
        var regs = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_REGS_BEGIN", "RANDFUZZ_REGS_END");
        var stack = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_STACK_BEGIN", "RANDFUZZ_STACK_END");
        var disasm = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_DISASM_BEGIN", "RANDFUZZ_DISASM_END");
        var mem = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_MEM_BEGIN", "RANDFUZZ_MEM_END");
        var exploitable = WindowsCdbCrashAnalysisWriter.ExtractBlock(text, "RANDFUZZ_EXPLOITABLE_BEGIN", "RANDFUZZ_EXPLOITABLE_END");

        // Keep raw analyze text updated (investigator may be the only CDB pass).
        var analyzePath = WindowsCdbCrashAnalysisWriter.AnalyzeTextPathFor(crashesDir, crashId);
        File.WriteAllText(analyzePath, string.IsNullOrWhiteSpace(analyze) ? text : analyze);
        if (msec is not null)
        {
            File.WriteAllText(
                WindowsCdbCrashAnalysisWriter.ExploitableTextPathFor(crashesDir, crashId),
                string.IsNullOrWhiteSpace(exploitable)
                    ? "(msec loaded but !exploitable produced no output)"
                    : exploitable);
        }

        var obs = BuildFromBlocks(
            dumpPath, obsPath, analyze, exr, regs, stack, disasm, mem, exploitable, timedOut, sidecar,
            timedOut
                ? $"cdb investigator timed out after {timeoutMs}ms — partial probes saved"
                : null);
        Write(obsPath, obs);
        return obs;
    }

    /// <summary>
    /// Persist observation from blocks already captured in a CDB session
    /// (used by <see cref="WindowsCdbCrashAnalysisWriter.Analyze"/> — one headless run).
    /// </summary>
    public static DebuggerObservation PersistFromCdbBlocks(
        string crashesDir,
        Guid crashId,
        string dumpPath,
        string analyze,
        string exr,
        string regs,
        string stack,
        string disasm,
        string mem,
        string exploitable,
        bool timedOut,
        CrashSidecarDto? sidecar)
    {
        var obsPath = ObservationPathFor(crashesDir, crashId);
        var obs = BuildFromBlocks(
            dumpPath, obsPath, analyze, exr, regs, stack, disasm, mem, exploitable, timedOut, sidecar,
            timedOut ? "cdb investigator timed out — partial probes saved" : null);
        Write(obsPath, obs);
        return obs;
    }

    /// <summary>Parse fixture / saved CDB blocks without launching cdb (tests).</summary>
    public static DebuggerObservation ParseBlocks(
        string analyze,
        string? exr = null,
        string? regs = null,
        string? stack = null,
        string? disasm = null,
        string? mem = null,
        string? exploitable = null,
        CrashSidecarDto? sidecar = null) =>
        BuildFromBlocks(
            dumpPath: null,
            obsPath: null,
            analyze: analyze,
            exr: exr ?? "",
            regs: regs ?? "",
            stack: stack ?? "",
            disasm: disasm ?? "",
            mem: mem ?? "",
            exploitable: exploitable ?? "",
            timedOut: false,
            sidecar: sidecar,
            error: null);

    private static DebuggerObservation BuildFromBlocks(
        string? dumpPath,
        string? obsPath,
        string analyze,
        string exr,
        string regs,
        string stack,
        string disasm,
        string mem,
        string exploitable,
        bool timedOut,
        CrashSidecarDto? sidecar,
        string? error)
    {
        var parsed = WindowsCdbCrashAnalysisWriter.ParseAnalyzeOutput(analyze);
        var exp = WindowsCdbCrashAnalysisWriter.ParseExploitableOutput(exploitable);
        var access = InferAccess(exr, analyze);
        // Prefer the accessed address from .exr (Parameter[1]) over FAULTING_IP for AVs.
        var faultAddr = ExtractFaultAddressFromExr(exr) ?? parsed.FaultAddress;
        var addrClass = ClassifyAddress(faultAddr);
        var rip = ExtractRip(regs, analyze) ?? faultAddr;
        var frames = ParseStackFrames(stack);
        var (fn, mod, fnOff) = InferFaultingSymbol(frames, parsed.FaultModule, analyze);
        var stackHash = HashStack(frames);
        var inputInfluence = InferInputInfluence(faultAddr, addrClass, regs, sidecar);
        var heapSignal = InferHeapSignal(analyze, exploitable, exp.Classification);
        var exploitHint = InferExploitHint(exp.Classification, access, addrClass, inputInfluence);
        var confidence = ComputeConfidence(parsed, frames, timedOut, error);
        var bonus = ComputeDebuggerBonus(exp.Classification, access, addrClass, inputInfluence, frames.Count);
        var diagnosis = BuildDiagnosis(
            parsed, access, faultAddr, addrClass, fn, mod, fnOff, exploitHint, inputInfluence, sidecar, heapSignal);

        var ok = !timedOut && (!string.IsNullOrWhiteSpace(parsed.ExceptionCode)
                               || !string.IsNullOrWhiteSpace(faultAddr)
                               || frames.Count > 0);

        return new DebuggerObservation(
            Ok: ok,
            DumpPath: dumpPath,
            ObservationPath: obsPath,
            ExceptionCode: parsed.ExceptionCode,
            ExceptionHint: parsed.ExceptionHint,
            Access: access,
            FaultAddress: faultAddr,
            FaultAddressClass: addrClass,
            Rip: rip,
            FaultingModule: mod ?? parsed.FaultModule,
            FaultingFunction: fn,
            FunctionOffset: fnOff,
            Stack: frames,
            StackHash: stackHash,
            RegistersText: Truncate(regs, 1200),
            DisasmNearRip: Truncate(disasm, 1600),
            MemoryNearRsp: Truncate(mem, 1200),
            ExrText: Truncate(exr, 800),
            ExploitableClassification: exp.Classification,
            ExploitableDescription: Truncate(exp.Description, 400),
            HeapSignal: heapSignal,
            SuspectedInputInfluence: inputInfluence,
            ExploitabilityHint: exploitHint,
            Confidence: confidence,
            Diagnosis: diagnosis,
            DebuggerScreamBonus: bonus,
            AnalyzeTimedOut: timedOut,
            Error: error,
            At: DateTimeOffset.UtcNow);
    }

    private static DebuggerObservation Empty(string? dumpPath, string? obsPath, string error) =>
        new(
            false, dumpPath, obsPath, null, null, DebuggerAccessKind.Unknown, null,
            DebuggerAddressClass.Unknown, null, null, null, null, [], null, null, null, null, null,
            null, null, null, "UNKNOWN", "UNKNOWN", 0, error, 0, false, error, DateTimeOffset.UtcNow);

    private static void Write(string path, DebuggerObservation obs) =>
        File.WriteAllText(path, JsonSerializer.Serialize(obs with { ObservationPath = path }, JsonOptions));

    private static string? ReadOptional(string path) =>
        File.Exists(path) ? File.ReadAllText(path) : null;

    private static DebuggerAccessKind InferAccess(string exr, string analyze)
    {
        var blob = exr + "\n" + analyze;
        if (Regex.IsMatch(blob, @"write|WRITE_ACCESS|attempted to write", RegexOptions.IgnoreCase))
            return DebuggerAccessKind.Write;
        if (Regex.IsMatch(blob, @"execute|DEP|NX|EXECUTE", RegexOptions.IgnoreCase))
            return DebuggerAccessKind.Execute;
        if (Regex.IsMatch(blob, @"read|READ_ACCESS|attempted to read", RegexOptions.IgnoreCase))
            return DebuggerAccessKind.Read;
        return DebuggerAccessKind.Unknown;
    }

    private static string? ExtractFaultAddressFromExr(string exr)
    {
        var m = Regex.Match(exr, @"(?:write to|read from)\s+address\s+([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        if (m.Success)
            return NormalizeAddr(m.Groups[1].Value);
        m = Regex.Match(exr, @"Parameter\[1\]:\s*([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        if (m.Success)
            return NormalizeAddr(m.Groups[1].Value);
        m = Regex.Match(exr, @"Address:\s*([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        return m.Success ? NormalizeAddr(m.Groups[1].Value) : null;
    }

    private static string? ExtractRip(string regs, string analyze)
    {
        var m = Regex.Match(regs, @"\brip=([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        if (m.Success)
            return NormalizeAddr(m.Groups[1].Value);
        m = Regex.Match(regs, @"\beip=([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        if (m.Success)
            return NormalizeAddr(m.Groups[1].Value);
        m = Regex.Match(analyze, @"FAULTING_IP:\s*([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase);
        return m.Success ? NormalizeAddr(m.Groups[1].Value) : null;
    }

    public static DebuggerAddressClass ClassifyAddress(string? addr)
    {
        if (string.IsNullOrWhiteSpace(addr) || addr.Contains('?', StringComparison.Ordinal))
            return DebuggerAddressClass.Unknown;
        if (!TryParseUlong(addr, out var v))
            return DebuggerAddressClass.Other;

        if (v < 0x1000)
            return DebuggerAddressClass.NullPage;
        if (v < 0x10000)
            return DebuggerAddressClass.SmallOffset;

        // ASCII-looking (e.g. 0x41414141) — check before stack heuristics.
        var b0 = (byte)(v & 0xFF);
        var b1 = (byte)((v >> 8) & 0xFF);
        var b2 = (byte)((v >> 16) & 0xFF);
        var b3 = (byte)((v >> 24) & 0xFF);
        static bool Printable(byte b) => b is >= 0x20 and <= 0x7e;
        if (Printable(b0) && Printable(b1) && Printable(b2) && Printable(b3)
            && (b0 == b1 || b0 is 0x41 or 0x42))
            return DebuggerAddressClass.AsciiPattern;

        // Non-canonical (high bits set oddly on x64 user)
        if (v > 0x00007FFFFFFFFFFFUL && v < 0xFFFF800000000000UL)
            return DebuggerAddressClass.NonCanonical;

        // Crude high user-stack band (exclude low 32-bit image placeholders).
        if (v >= 0x00007FF000000000UL && v <= 0x00007FFFFFFFFFFFUL)
            return DebuggerAddressClass.Stackish;

        return DebuggerAddressClass.Other;
    }

    private static List<DebuggerStackFrameDto> ParseStackFrames(string stack)
    {
        var frames = new List<DebuggerStackFrameDto>();
        if (string.IsNullOrWhiteSpace(stack))
            return frames;

        var idx = 0;
        foreach (var raw in stack.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("Child", StringComparison.OrdinalIgnoreCase))
                continue;

            // Typical: 00 00000000`0012ff00 00007ff6`12345678 randall_vulndrone!HandleHello+0x42
            var m = StackFrameLine().Match(line);
            if (!m.Success)
                continue;

            var sym = m.Groups["sym"].Value.Trim();
            string? module = null;
            string? function = null;
            string? offset = null;
            var bang = sym.IndexOf('!', StringComparison.Ordinal);
            if (bang > 0)
            {
                module = sym[..bang];
                var rest = sym[(bang + 1)..];
                var plus = rest.IndexOf("+0x", StringComparison.OrdinalIgnoreCase);
                if (plus > 0)
                {
                    function = rest[..plus];
                    offset = rest[plus..];
                }
                else
                    function = rest;
            }

            frames.Add(new DebuggerStackFrameDto(
                idx++,
                m.Groups["ret"].Success ? NormalizeAddr(m.Groups["ret"].Value.Replace("`", "", StringComparison.Ordinal)) : null,
                module,
                function ?? (string.IsNullOrWhiteSpace(sym) ? null : sym),
                offset));

            if (frames.Count >= 16)
                break;
        }

        return frames;
    }

    private static (string? Function, string? Module, string? Offset) InferFaultingSymbol(
        IReadOnlyList<DebuggerStackFrameDto> frames,
        string? analyzeModule,
        string analyze)
    {
        if (frames.Count > 0)
        {
            var f0 = frames[0];
            return (f0.Symbol, f0.Module ?? analyzeModule, f0.Offset);
        }

        var m = Regex.Match(analyze, @"FAULTING_SOURCE_CODE:[\s\S]*?(\w+)!(\w+)\+0x([0-9A-Fa-f]+)",
            RegexOptions.IgnoreCase);
        if (m.Success)
            return (m.Groups[2].Value, m.Groups[1].Value, "+0x" + m.Groups[3].Value);

        return (null, analyzeModule, null);
    }

    private static string? HashStack(IReadOnlyList<DebuggerStackFrameDto> frames)
    {
        if (frames.Count == 0)
            return null;
        var key = string.Join('|', frames.Take(8).Select(f =>
            $"{f.Module ?? "?"}:{f.Symbol ?? "?"}:{f.Offset ?? ""}"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(hash.AsSpan(0, 8));
    }

    private static string InferInputInfluence(
        string? faultAddr,
        DebuggerAddressClass addrClass,
        string regs,
        CrashSidecarDto? sidecar)
    {
        if (addrClass == DebuggerAddressClass.AsciiPattern)
            return "HIGH";

        if (Regex.IsMatch(regs, @"=0*41{4,}|={2,}[Bb]{4,}", RegexOptions.IgnoreCase))
            return "HIGH";

        var mut = sidecar?.Mutator ?? "";
        if (mut.Contains("expand", StringComparison.OrdinalIgnoreCase)
            || mut.Contains("insert", StringComparison.OrdinalIgnoreCase)
            || mut.Contains("havoc", StringComparison.OrdinalIgnoreCase))
        {
            if (addrClass is DebuggerAddressClass.NullPage or DebuggerAddressClass.SmallOffset)
                return "MEDIUM";
            return "MEDIUM";
        }

        if (faultAddr is not null && TryParseUlong(faultAddr, out var v) && v is 0xCCCCCCCC or 0xDDDDDDDD or 0xFEEEFEEE)
            return "MEDIUM";

        return "UNKNOWN";
    }

    private static string? InferHeapSignal(string analyze, string exploitable, string? classification)
    {
        var blob = analyze + "\n" + exploitable;
        if (Regex.IsMatch(blob, @"heap.?corrupt|HEAP_CORRUPTION|!heap", RegexOptions.IgnoreCase))
            return "HEAP_CORRUPTION";
        if (classification?.Contains("HEAP", StringComparison.OrdinalIgnoreCase) == true)
            return "HEAP_SIGNAL";
        if (Regex.IsMatch(blob, @"use.?after.?free|UAF", RegexOptions.IgnoreCase))
            return "USE_AFTER_FREE";
        return null;
    }

    private static string InferExploitHint(
        string? classification,
        DebuggerAccessKind access,
        DebuggerAddressClass addrClass,
        string inputInfluence)
    {
        var c = (classification ?? "").ToUpperInvariant();
        if (c is "EXPLOITABLE" or "PROBABLY_EXPLOITABLE")
            return "HIGH";
        if (access == DebuggerAccessKind.Write && addrClass == DebuggerAddressClass.AsciiPattern)
            return "HIGH";
        if (inputInfluence == "HIGH" && access is DebuggerAccessKind.Write or DebuggerAccessKind.Execute)
            return "HIGH";
        if (c is "PROBABLY_NOT_EXPLOITABLE")
            return "LOW";
        if (access == DebuggerAccessKind.Write || inputInfluence == "HIGH")
            return "MEDIUM";
        return string.IsNullOrWhiteSpace(c) ? "UNKNOWN" : "MEDIUM";
    }

    private static double ComputeConfidence(
        WindowsCdbCrashAnalysisWriter.ParsedAnalyze parsed,
        IReadOnlyList<DebuggerStackFrameDto> frames,
        bool timedOut,
        string? error)
    {
        if (error is not null && frames.Count == 0 && parsed.ExceptionCode is null)
            return 0.15;
        var c = 0.55;
        if (parsed.ExceptionCode is not null) c += 0.15;
        if (parsed.FaultAddress is not null) c += 0.1;
        if (frames.Count > 0) c += 0.12;
        if (timedOut) c -= 0.2;
        return Math.Clamp(c, 0.1, 0.98);
    }

    private static int ComputeDebuggerBonus(
        string? classification,
        DebuggerAccessKind access,
        DebuggerAddressClass addrClass,
        string inputInfluence,
        int frameCount)
    {
        var bonus = 0;
        var c = (classification ?? "").ToUpperInvariant();
        if (c == "EXPLOITABLE") bonus += 18;
        else if (c == "PROBABLY_EXPLOITABLE") bonus += 12;
        if (access == DebuggerAccessKind.Write) bonus += 8;
        if (access == DebuggerAccessKind.Execute) bonus += 10;
        if (addrClass == DebuggerAddressClass.AsciiPattern) bonus += 10;
        if (inputInfluence == "HIGH") bonus += 8;
        if (frameCount >= 3) bonus += 4;
        return Math.Clamp(bonus, 0, 40);
    }

    private static string BuildDiagnosis(
        WindowsCdbCrashAnalysisWriter.ParsedAnalyze parsed,
        DebuggerAccessKind access,
        string? faultAddr,
        DebuggerAddressClass addrClass,
        string? fn,
        string? mod,
        string? fnOff,
        string exploitHint,
        string inputInfluence,
        CrashSidecarDto? sidecar,
        string? heapSignal)
    {
        var where = fn is not null
            ? $"{mod ?? "?"}!{fn}{fnOff ?? ""}"
            : faultAddr ?? parsed.FaultAddress ?? "unknown RIP";

        var accessWord = access switch
        {
            DebuggerAccessKind.Write => "Write",
            DebuggerAccessKind.Read => "Read",
            DebuggerAccessKind.Execute => "Execute",
            _ => "Fault",
        };

        var hint = parsed.ExceptionHint ?? "ACCESS_VIOLATION";
        var sb = new StringBuilder();
        sb.Append($"{accessWord} {hint} in {where}.");
        if (faultAddr is not null)
            sb.Append($" Fault address {faultAddr} ({addrClass}).");
        if (heapSignal is not null)
            sb.Append($" Heap signal: {heapSignal}.");
        if (sidecar?.Command is not null || sidecar?.Mutator is not null)
        {
            sb.Append($" Trigger: {sidecar.Command ?? "?"} / {sidecar.Mutator ?? "?"}.");
        }

        if (inputInfluence is "HIGH" or "MEDIUM")
            sb.Append($" Suspected input influence: {inputInfluence}.");
        sb.Append($" Exploitability hint: {exploitHint}.");
        return sb.ToString();
    }

    private static bool TryParseUlong(string addr, out ulong v)
    {
        v = 0;
        var h = addr.Trim();
        if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            h = h[2..];
        h = h.Replace("`", "", StringComparison.Ordinal);
        return ulong.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
    }

    private static string? NormalizeAddr(string addr)
    {
        var a = addr.Trim().Replace("`", "", StringComparison.Ordinal);
        if (!a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            a = "0x" + a;
        return a;
    }

    private static string? Truncate(string? s, int max)
    {
        if (string.IsNullOrWhiteSpace(s))
            return null;
        s = s.Trim();
        return s.Length <= max ? s : s[..max] + "…";
    }

    // Child-SP              RetAddr               Call Site
    // 00000000`0012ff00     00007ff6`12345678     module!func+0x42
    [GeneratedRegex(
        @"^(?:[0-9A-Fa-f`]+)\s+(?<ret>[0-9A-Fa-fx`]+)\s+(?<sym>\S+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex StackFrameLine();
}
