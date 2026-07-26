using System.Security.Cryptography;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Stable semantic crash fingerprint for dedup/clustering beyond raw PC buckets.
/// Combines exception class, access/address class, faulting function, normalized stack,
/// heap signal, controlled input offset, oracle violation, coverage tail, and corruption chain.
/// </summary>
public static class SemanticCrashFingerprint
{
    /// <summary>Grouping key — prefers semantic fingerprint when present, else legacy cluster key.</summary>
    public static string ClusterGroupKey(CrashTriageDto triage) =>
        !string.IsNullOrWhiteSpace(triage.SemanticFingerprint)
            ? triage.SemanticFingerprint!
            : triage.ClusterKey;

    public static string Build(
        string exceptionClass,
        DebuggerObservation? debugger = null,
        CrashSidecarDto? sidecar = null,
        CrashCorruptionChainDto? corruptionChain = null,
        int? controlledInputOffset = null,
        CrashTriageDto? triage = null)
    {
        var exc = NormalizeToken(exceptionClass);
        var access = debugger?.Access ?? DebuggerAccessKind.Unknown;
        var addrClass = debugger?.FaultAddressClass ?? InferAddressClass(triage);
        var fn = NormalizeFunction(debugger?.FaultingFunction, debugger?.FaultingModule)
                 ?? NormalizeFunction(triage?.StaticFunction?.FunctionName, null);
        var frames = FormatTopFrames(debugger?.Stack);
        var heap = string.IsNullOrWhiteSpace(debugger?.HeapSignal)
            ? "none"
            : NormalizeToken(debugger!.HeapSignal!);
        var offset = controlledInputOffset ?? triage?.PatternDepthBytes;
        var offToken = offset is int d ? $"0x{d:x}" : "none";
        var oracle = InferOracleViolation(sidecar) ?? "none";
        var cov = BucketCoverageTail(sidecar?.NewEdgesAtCrash);
        var chain = ChainSignature(corruptionChain);

        return string.Join(':',
            $"exc={exc}",
            $"acc={access.ToString().ToLowerInvariant()}",
            $"addr={addrClass.ToString().ToLowerInvariant()}",
            $"fn={fn ?? "unk"}",
            $"stk={frames ?? "none"}",
            $"heap={heap}",
            $"off={offToken}",
            $"ora={oracle}",
            $"cov={cov}",
            $"chain={chain}");
    }

    public static string? InferOracleViolation(CrashSidecarDto? sidecar)
    {
        if (sidecar?.RandallScore?.Terms is { Count: > 0 } terms)
        {
            foreach (var term in terms)
            {
                if (term.Label.Contains("violation", StringComparison.OrdinalIgnoreCase)
                    || term.Detail?.Contains("violation", StringComparison.OrdinalIgnoreCase) == true)
                    return NormalizeToken(term.Label);
            }
        }

        var detail = sidecar?.TargetDetail ?? sidecar?.ExceptionHint ?? "";
        if (detail.Contains("violation", StringComparison.OrdinalIgnoreCase))
            return "runtime-violation";

        return null;
    }

    public static string BucketCoverageTail(int? newEdgesAtCrash) => newEdgesAtCrash switch
    {
        null or <= 0 => "none",
        <= 2 => "tail-low",
        <= 10 => "tail-mid",
        _ => "tail-high",
    };

    private static DebuggerAddressClass InferAddressClass(CrashTriageDto? triage)
    {
        if (triage?.IpLooksControlled == true)
            return DebuggerAddressClass.AsciiPattern;
        if (triage?.StackLooksSmashed == true)
            return DebuggerAddressClass.Stackish;
        return DebuggerAddressClass.Unknown;
    }

    private static string? NormalizeFunction(string? function, string? module)
    {
        if (string.IsNullOrWhiteSpace(function))
            return null;
        var fn = function.Trim().ToLowerInvariant();
        var plus = fn.IndexOf("+0x", StringComparison.OrdinalIgnoreCase);
        if (plus > 0)
            fn = fn[..plus];
        if (!string.IsNullOrWhiteSpace(module))
        {
            var mod = Path.GetFileName(module).ToLowerInvariant();
            return $"{mod}!{fn}";
        }

        return fn;
    }

    private static string? FormatTopFrames(IReadOnlyList<DebuggerStackFrameDto>? stack)
    {
        if (stack is null || stack.Count == 0)
            return null;

        var parts = stack.Take(4).Select(f =>
        {
            var mod = string.IsNullOrWhiteSpace(f.Module)
                ? "?"
                : Path.GetFileName(f.Module).ToLowerInvariant();
            var sym = string.IsNullOrWhiteSpace(f.Symbol) ? "?" : f.Symbol.ToLowerInvariant();
            var plus = sym.IndexOf("+0x", StringComparison.OrdinalIgnoreCase);
            if (plus > 0)
                sym = sym[..plus];
            return $"{mod}!{sym}";
        });
        return string.Join(">", parts);
    }

    private static string ChainSignature(CrashCorruptionChainDto? chain)
    {
        if (chain is not { Ok: true })
            return "none";
        if (string.IsNullOrWhiteSpace(chain.Summary) && chain.Steps.Count == 0)
            return "none";

        var key = chain.Summary + "|" + string.Join(",",
            chain.Steps.Select(s => $"{s.Kind}:{s.Label}"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(hash.AsSpan(0, 6)).ToLowerInvariant();
    }

    private static string NormalizeToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "unknown";
        return value.Trim().ToLowerInvariant().Replace(' ', '-');
    }
}
