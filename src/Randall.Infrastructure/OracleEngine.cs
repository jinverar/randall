using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public enum OracleSeverity
{
    None = 0,
    NearMiss = 1,
    Violation = 2,
    Runtime = 3,
}

public sealed record OracleEvalResult(
    OracleSeverity MaxSeverity,
    int InterestingnessScore,
    IReadOnlyList<OracleFindingDto> Findings,
    bool RetainInCorpus,
    int EnergyBoost,
    string Summary);

/// <summary>
/// Hybrid semantic oracle stack: runtime → invariant → differential → metamorphic.
/// Coverage still guides exploration; oracle findings feed corpus energy + persistence.
/// </summary>
public static class OracleEngine
{
    public static bool IsEnabled(ProjectConfig project) =>
        project.Oracles is { Enabled: true };

    public static async Task<OracleEvalResult> EvaluateAsync(
        OracleObservation obs,
        CancellationToken ct = default)
    {
        var cfg = obs.Project.Oracles ?? new OracleConfig { Enabled = false };
        if (!cfg.Enabled)
            return new OracleEvalResult(OracleSeverity.None, 0, [], false, 0, "");

        var findings = new List<OracleFindingDto>();
        EvaluateRuntime(obs, findings);
        EvaluateInvariants(obs, cfg, findings);
        await EvaluateDifferentialAsync(obs, cfg, findings, ct);
        await EvaluateMetamorphicAsync(obs, cfg, findings, ct);

        var max = OracleSeverity.None;
        foreach (var f in findings)
            max = Max(max, ParseSeverity(f.Severity));

        var score = Score(obs, findings, max);
        var retain = max switch
        {
            OracleSeverity.Runtime => false, // crashes already handled
            OracleSeverity.Violation => cfg.RetainOnViolation,
            OracleSeverity.NearMiss => cfg.RetainOnNearMiss,
            _ => false,
        };
        var boost = max switch
        {
            OracleSeverity.Violation => 8,
            OracleSeverity.NearMiss => 3,
            OracleSeverity.Runtime => 0,
            _ => 0,
        };

        var summary = findings.Count == 0
            ? ""
            : string.Join("; ", findings.Select(f => $"{f.RuleClass}/{f.RuleId}:{f.Severity}"));

        return new OracleEvalResult(max, score, findings, retain, boost, summary);
    }

    public static void PersistFindings(
        ProjectConfig project,
        string yamlPath,
        OracleEvalResult eval)
    {
        if (project.Oracles is not { PersistFindings: true } || eval.Findings.Count == 0)
            return;
        var dir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir),
            "_oracles");
        var store = new OracleFindingStore(dir);
        foreach (var f in eval.Findings)
            store.Append(f);
    }

    private static void EvaluateRuntime(OracleObservation obs, List<OracleFindingDto> findings)
    {
        if (obs.Result.Crashed)
        {
            findings.Add(MakeFinding(obs, "runtime.crash", "RuntimeRule", "runtime", 0.99,
                "process stays alive",
                $"crashed exit={obs.Result.ExitCode} detail={obs.Result.Detail}",
                NormalizeObservation(obs.Result),
                transformation: null));
        }

        var detail = obs.Result.Detail ?? "";
        if (detail.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("timed out", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(MakeFinding(obs, "runtime.timeout", "RuntimeRule", "runtime", 0.9,
                "completes within timeout", detail, NormalizeObservation(obs.Result), null));
        }

        if (LooksLikeSanitizer(detail))
        {
            findings.Add(MakeFinding(obs, "runtime.sanitizer", "RuntimeRule", "runtime", 0.95,
                "no sanitizer report", detail, NormalizeObservation(obs.Result), null));
        }
    }

    private static void EvaluateInvariants(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        // Promote session expectResponse mismatch (when TargetRunner left soft Detail).
        if (cfg.PromoteExpectResponse &&
            !obs.Result.Crashed &&
            !string.IsNullOrWhiteSpace(obs.ExpectResponsePattern) &&
            !ResponseMatcher.Matches(obs.Result.ResponseBytes, obs.ExpectResponsePattern))
        {
            var sev = cfg.InvariantSeverity.Equals("nearMiss", StringComparison.OrdinalIgnoreCase)
                ? "nearMiss"
                : "violation";
            findings.Add(MakeFinding(obs, "invariant.expectResponse", "InvariantRule", sev, 0.85,
                $"response contains '{obs.ExpectResponsePattern}'",
                $"got {ResponseMatcher.Describe(obs.Result.ResponseBytes)}",
                NormalizeObservation(obs.Result),
                null));
        }

        if (cfg.PromotePostReceiveAbort &&
            !obs.Result.Crashed &&
            !string.IsNullOrWhiteSpace(obs.PluginAbortDetail))
        {
            findings.Add(MakeFinding(obs, "invariant.post_receive", "InvariantRule", "violation", 0.8,
                "post_receive continue",
                obs.PluginAbortDetail!,
                NormalizeObservation(obs.Result),
                null));
        }

        foreach (var rule in cfg.Invariants)
        {
            if (!CommandMatches(obs.CommandName, rule.WhenCommand))
                continue;
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "invariant") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "violation" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();

            switch (type)
            {
                case "expectsubstring" or "expect":
                    if (!ResponseMatcher.Matches(obs.Result.ResponseBytes, rule.Pattern))
                    {
                        findings.Add(MakeFinding(obs, id, "InvariantRule", sev, 0.85,
                            $"response contains '{rule.Pattern}'",
                            $"got {ResponseMatcher.Describe(obs.Result.ResponseBytes)}",
                            NormalizeObservation(obs.Result), null));
                    }
                    break;
                case "forbidsubstring" or "forbid":
                    if (!string.IsNullOrWhiteSpace(rule.Pattern) &&
                        ResponseMatcher.Matches(obs.Result.ResponseBytes, rule.Pattern))
                    {
                        findings.Add(MakeFinding(obs, id, "InvariantRule", sev, 0.9,
                            $"response must not contain '{rule.Pattern}'",
                            $"got {ResponseMatcher.Describe(obs.Result.ResponseBytes)}",
                            NormalizeObservation(obs.Result), null));
                    }
                    break;
                case "maxresponsebytes" or "maxbytes":
                    var max = rule.MaxBytes ?? 0;
                    var len = obs.Result.ResponseBytes?.Length ?? 0;
                    if (max > 0 && len > max)
                    {
                        findings.Add(MakeFinding(obs, id, "InvariantRule", sev, 0.7,
                            $"response length ≤ {max}",
                            $"length={len}",
                            NormalizeObservation(obs.Result), null));
                    }
                    break;
                case "exitcodezero":
                    if (obs.Result.ExitCode is int z && z != 0 && !obs.Result.Crashed)
                    {
                        findings.Add(MakeFinding(obs, id, "InvariantRule", sev, 0.75,
                            "exit code == 0", $"exit={z}", NormalizeObservation(obs.Result), null));
                    }
                    break;
                case "exitcodenonzero":
                    if (obs.Result.ExitCode is 0)
                    {
                        findings.Add(MakeFinding(obs, id, "InvariantRule", sev, 0.75,
                            "exit code != 0", "exit=0", NormalizeObservation(obs.Result), null));
                    }
                    break;
            }
        }
    }

    private static async Task EvaluateDifferentialAsync(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings,
        CancellationToken ct)
    {
        if (cfg.Differential.Count == 0)
            return;
        if (!obs.Project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase))
            return; // v1: file harness only

        foreach (var rule in cfg.Differential)
        {
            if (string.IsNullOrWhiteSpace(rule.ReferenceExecutable))
                continue;
            ct.ThrowIfCancellationRequested();
            var id = string.IsNullOrWhiteSpace(rule.Id) ? "differential.ref" : rule.Id;
            try
            {
                var refRun = await RunReferenceFileAsync(obs, rule, ct);
                var type = (rule.Type ?? "fileExit").Trim().ToLowerInvariant();
                if (type is "fileexit" or "exit")
                {
                    var a = obs.Result.ExitCode ?? (obs.Result.Crashed ? -1 : 0);
                    var b = refRun.ExitCode ?? (refRun.Crashed ? -1 : 0);
                    // Normalize crash vs non-zero: compare crash-class
                    var aClass = obs.Result.Crashed ? "crash" : (a == 0 ? "ok" : "error");
                    var bClass = refRun.Crashed ? "crash" : (b == 0 ? "ok" : "error");
                    if (!string.Equals(aClass, bClass, StringComparison.Ordinal))
                    {
                        findings.Add(MakeFinding(obs, id, "DifferentialRule", "violation", 0.8,
                            $"status_class matches reference ({bClass})",
                            $"target={aClass} reference={bClass}",
                            $"{{\"target\":\"{aClass}\",\"reference\":\"{bClass}\"}}",
                            "referenceExecutable"));
                    }
                }
                else if (type is "fileresponse" or "response")
                {
                    var a = NormalizeText(obs.Result.ResponseBytes);
                    var b = NormalizeText(refRun.ResponseBytes);
                    if (!string.Equals(a, b, StringComparison.Ordinal))
                    {
                        // Structural near-miss if both empty/non-empty match
                        var sev = (string.IsNullOrEmpty(a) == string.IsNullOrEmpty(b))
                            ? "nearMiss"
                            : "violation";
                        findings.Add(MakeFinding(obs, id, "DifferentialRule", sev, 0.7,
                            "normalized response matches reference",
                            $"target='{Truncate(a, 80)}' ref='{Truncate(b, 80)}'",
                            $"{{\"target_len\":{(obs.Result.ResponseBytes?.Length ?? 0)},\"ref_len\":{(refRun.ResponseBytes?.Length ?? 0)}}}",
                            "referenceExecutable"));
                    }
                }
            }
            catch (Exception ex)
            {
                // Soft-fail differential — don't poison the campaign.
                Console.Error.WriteLine($"Oracle differential '{id}' skipped: {ex.Message}");
            }
        }
    }

    private static async Task EvaluateMetamorphicAsync(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings,
        CancellationToken ct)
    {
        foreach (var rule in cfg.Metamorphic)
        {
            ct.ThrowIfCancellationRequested();
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "metamorphic") : rule.Id;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "nearMiss" : rule.Severity;

            try
            {
                if (type is "whitespaceinsensitive" or "whitespace")
                {
                    if (obs.Result.Crashed)
                        continue;
                    var transformed = CollapseWhitespace(obs.Payload);
                    if (transformed.AsSpan().SequenceEqual(obs.Payload))
                        continue;

                    var second = await TargetRunner.RunPayloadAsync(
                        obs.Project, obs.YamlPath, transformed, longLivedServer: null, ct);
                    if (second.Crashed)
                    {
                        findings.Add(MakeFinding(obs, id, "MetamorphicRule", sev, 0.75,
                            "whitespace-normalized input preserves non-crash",
                            $"transformed crashed: {second.Detail}",
                            NormalizeObservation(second),
                            "collapseWhitespace"));
                        continue;
                    }

                    var a = ResponseClass(obs.Result.ResponseBytes);
                    var b = ResponseClass(second.ResponseBytes);
                    if (!string.Equals(a, b, StringComparison.Ordinal))
                    {
                        findings.Add(MakeFinding(obs, id, "MetamorphicRule", sev, 0.7,
                            "response class invariant under whitespace normalize",
                            $"original={a} transformed={b}",
                            $"{{\"original\":\"{a}\",\"transformed\":\"{b}\"}}",
                            "collapseWhitespace"));
                    }
                }
                else if (type is "duplicateidempotent" or "idempotent")
                {
                    if (!obs.Project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (obs.Result.Crashed)
                        continue;

                    var second = await TargetRunner.RunPayloadAsync(
                        obs.Project, obs.YamlPath, obs.Payload, longLivedServer: null, ct);
                    var a = ResponseClass(obs.Result.ResponseBytes);
                    var b = ResponseClass(second.ResponseBytes);
                    if (!string.Equals(a, b, StringComparison.Ordinal) || second.Crashed != obs.Result.Crashed)
                    {
                        findings.Add(MakeFinding(obs, id, "MetamorphicRule", sev, 0.65,
                            "duplicate request preserves response class",
                            $"first={a} crashed={obs.Result.Crashed}; second={b} crashed={second.Crashed}",
                            $"{{\"first\":\"{a}\",\"second\":\"{b}\"}}",
                            "duplicateRequest"));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Oracle metamorphic '{id}' skipped: {ex.Message}");
            }
        }
    }

    private static async Task<TargetRunResult> RunReferenceFileAsync(
        OracleObservation obs,
        OracleDifferentialRuleConfig rule,
        CancellationToken ct)
    {
        var exeDeclared = ProjectLoader.ResolvePath(obs.YamlPath, rule.ReferenceExecutable);
        var exe = ExecutableResolver.FindExisting(exeDeclared)
            ?? throw new FileNotFoundException($"reference executable not found: {exeDeclared}");

        var tmp = Path.Combine(Path.GetTempPath(), $"randall_oracle_{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(tmp, obs.Payload, ct);
        try
        {
            var args = rule.ReferenceArgs.Count > 0 ? rule.ReferenceArgs : ["@@"];
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (var a in args)
            {
                psi.ArgumentList.Add(
                    a.Replace("@@", tmp, StringComparison.Ordinal)
                     .Replace("{file}", tmp, StringComparison.OrdinalIgnoreCase));
            }

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("failed to start reference");
            var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            _ = await proc.StandardError.ReadToEndAsync(ct);
            var completed = proc.WaitForExit(Math.Max(250, rule.TimeoutMs));
            if (!completed)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new TargetRunResult(true, null, null, "reference timeout",
                    Encoding.UTF8.GetBytes(stdout));
            }

            var crashed = proc.ExitCode < 0 || proc.ExitCode == 139 || proc.ExitCode == 134;
            return new TargetRunResult(crashed, proc.ExitCode, null,
                crashed ? $"reference exit={proc.ExitCode}" : "ok",
                Encoding.UTF8.GetBytes(stdout));
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* ignore */ }
        }
    }

    private static int Score(OracleObservation obs, List<OracleFindingDto> findings, OracleSeverity max)
    {
        var score = obs.NewEdges * 10;
        foreach (var f in findings)
        {
            score += ParseSeverity(f.Severity) switch
            {
                OracleSeverity.Runtime => 100,
                OracleSeverity.Violation => 100,
                OracleSeverity.NearMiss => 12,
                _ => 0,
            };
        }

        // Output-shape signal: non-empty response with no prior expectation.
        if (obs.Result.ResponseBytes is { Length: > 0 } && findings.Count == 0 && obs.NewEdges == 0)
            score += 0;

        _ = max;
        return score;
    }

    private static OracleFindingDto MakeFinding(
        OracleObservation obs,
        string ruleId,
        string ruleClass,
        string severity,
        double confidence,
        string expected,
        string actual,
        string? normalized,
        string? transformation)
    {
        var covSig = obs.NewEdges > 0
            ? $"edges+{obs.NewEdges}/{obs.CoverageEdgeTotal}"
            : $"edges={obs.CoverageEdgeTotal}";
        return new OracleFindingDto(
            Guid.NewGuid().ToString("N"),
            obs.Project.Name,
            ruleId ?? "unknown",
            ruleClass,
            severity,
            confidence,
            InputHash.StackHash(obs.Payload),
            obs.CommandName,
            obs.MutatorName,
            obs.Iteration,
            expected,
            actual,
            normalized,
            transformation,
            covSig,
            1,
            DateTimeOffset.UtcNow);
    }

    private static string NormalizeObservation(TargetRunResult r)
    {
        var obj = new
        {
            status_class = r.Crashed ? "crash" : (r.ExitCode is 0 or null ? "success" : "error"),
            exit = r.ExitCode,
            response_len = r.ResponseBytes?.Length ?? 0,
            response_class = ResponseClass(r.ResponseBytes),
        };
        return JsonSerializer.Serialize(obj);
    }

    private static string ResponseClass(byte[]? response)
    {
        if (response is null || response.Length == 0)
            return "empty";
        var text = Encoding.ASCII.GetString(response);
        // First token / status-ish prefix
        var trimmed = text.Trim();
        if (trimmed.Length == 0)
            return "empty";
        var token = Regex.Match(trimmed, @"^[A-Za-z0-9_+\-]+");
        if (token.Success)
            return token.Value.ToLowerInvariant();
        return trimmed.Length < 16 ? "short" : "binaryish";
    }

    private static string NormalizeText(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
            return "";
        var t = Encoding.UTF8.GetString(bytes);
        t = Regex.Replace(t, @"\s+", " ").Trim();
        // Drop obvious nondeterminism markers
        t = Regex.Replace(t, @"\b\d{10,}\b", "<num>");
        return t;
    }

    private static byte[] CollapseWhitespace(byte[] payload)
    {
        try
        {
            var t = Encoding.UTF8.GetString(payload);
            if (t.Any(c => c > 127))
                return payload; // binary — leave alone
            var collapsed = Regex.Replace(t, @"[ \t]+", " ");
            collapsed = Regex.Replace(collapsed, @"\r\n|\r|\n", "\n");
            return Encoding.UTF8.GetBytes(collapsed);
        }
        catch
        {
            return payload;
        }
    }

    private static bool CommandMatches(string? command, string? when) =>
        string.IsNullOrWhiteSpace(when) ||
        (!string.IsNullOrWhiteSpace(command) &&
         command.Contains(when, StringComparison.OrdinalIgnoreCase));

    private static bool LooksLikeSanitizer(string detail) =>
        detail.Contains("AddressSanitizer", StringComparison.OrdinalIgnoreCase) ||
        detail.Contains("UndefinedBehaviorSanitizer", StringComparison.OrdinalIgnoreCase) ||
        detail.Contains("MemorySanitizer", StringComparison.OrdinalIgnoreCase) ||
        detail.Contains("ThreadSanitizer", StringComparison.OrdinalIgnoreCase) ||
        detail.Contains("heap-buffer-overflow", StringComparison.OrdinalIgnoreCase) ||
        detail.Contains("stack-buffer-overflow", StringComparison.OrdinalIgnoreCase);

    private static OracleSeverity ParseSeverity(string s) =>
        s.Trim().ToLowerInvariant() switch
        {
            "runtime" => OracleSeverity.Runtime,
            "violation" => OracleSeverity.Violation,
            "nearmiss" or "near_miss" or "near-miss" => OracleSeverity.NearMiss,
            _ => OracleSeverity.None,
        };

    private static OracleSeverity Max(OracleSeverity a, OracleSeverity b) => a > b ? a : b;

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
