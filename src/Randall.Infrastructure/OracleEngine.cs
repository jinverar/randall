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
/// Hybrid semantic oracle stack focused on logic / auth / state / structure bugs
/// (especially for memory-safe targets). Coverage still guides exploration.
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
        EvaluateAuth(obs, cfg, findings);
        EvaluateState(obs, cfg, findings);
        EvaluateInteger(obs, cfg, findings);
        EvaluateStructure(obs, cfg, findings);
        EvaluateResource(obs, cfg, findings);
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

    private static void EvaluateAuth(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        var session = obs.Session;
        foreach (var rule in cfg.Auth)
        {
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "auth") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "violation" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();

            switch (type)
            {
                case "forbiduntil":
                {
                    if (string.IsNullOrWhiteSpace(rule.ForbidResponse))
                        break;
                    var authed = session?.HasResponseMarker(rule.UntilResponse) == true
                                 || session?.Authenticated == true;
                    if (!authed &&
                        ResponseMatcher.Matches(obs.Result.ResponseBytes, rule.ForbidResponse))
                    {
                        findings.Add(MakeFinding(obs, id, "AuthRule", sev, 0.9,
                            $"must not see '{rule.ForbidResponse}' before '{rule.UntilResponse}'",
                            $"got privileged/success response pre-auth; session={session?.Snapshot()}",
                            NormalizeObservation(obs.Result),
                            "auth.forbidUntil"));
                    }
                    break;
                }
                case "requireauth":
                {
                    if (!CommandMatches(obs.CommandName, rule.WhenCommand))
                        break;
                    var authed = session?.HasResponseMarker(rule.UntilResponse) == true
                                 || session?.Authenticated == true;
                    if (!authed)
                    {
                        // Near-miss if rejected; violation if accepted (success-class response)
                        var accepted = LooksAccepted(obs.Result);
                        var useSev = accepted ? sev : "nearMiss";
                        findings.Add(MakeFinding(obs, id, "AuthRule", useSev, accepted ? 0.9 : 0.6,
                            $"command '{rule.WhenCommand}' requires prior '{rule.UntilResponse}'",
                            $"session={session?.Snapshot()}; accepted={accepted}",
                            NormalizeObservation(obs.Result),
                            "auth.requireAuth"));
                    }
                    break;
                }
            }
        }
    }

    private static void EvaluateState(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        var session = obs.Session;
        foreach (var rule in cfg.State)
        {
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "state") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "violation" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();

            switch (type)
            {
                case "commandrequiresprior":
                {
                    if (!CommandMatches(obs.CommandName, rule.ForCommand))
                        break;
                    var priorOk = session?.HasCommand(rule.PriorCommand) == true;
                    if (!string.IsNullOrWhiteSpace(rule.PriorResponse))
                        priorOk = priorOk && session?.HasResponseMarker(rule.PriorResponse) == true;

                    if (!priorOk)
                    {
                        var accepted = LooksAccepted(obs.Result);
                        findings.Add(MakeFinding(obs, id, "StateRule", accepted ? sev : "nearMiss",
                            accepted ? 0.9 : 0.55,
                            $"'{rule.ForCommand}' requires prior '{rule.PriorCommand}'" +
                            (string.IsNullOrWhiteSpace(rule.PriorResponse) ? "" : $"/{rule.PriorResponse}"),
                            $"session={session?.Snapshot()}; accepted={accepted}",
                            NormalizeObservation(obs.Result),
                            "state.commandRequiresPrior"));
                    }
                    break;
                }
                case "forbidresponseinstate":
                {
                    if (string.IsNullOrWhiteSpace(rule.ForbidResponse))
                        break;
                    var unlocked = session?.HasResponseMarker(rule.UntilResponse) == true;
                    if (!unlocked &&
                        ResponseMatcher.Matches(obs.Result.ResponseBytes, rule.ForbidResponse))
                    {
                        findings.Add(MakeFinding(obs, id, "StateRule", sev, 0.85,
                            $"response '{rule.ForbidResponse}' forbidden until '{rule.UntilResponse}'",
                            $"session={session?.Snapshot()}",
                            NormalizeObservation(obs.Result),
                            "state.forbidResponseInState"));
                    }
                    break;
                }
            }
        }
    }

    private static void EvaluateInteger(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        foreach (var rule in cfg.Integer)
        {
            if (!CommandMatches(obs.CommandName, rule.WhenCommand))
                continue;
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "integer") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "violation" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();
            var width = rule.Width is 1 or 2 or 4 ? rule.Width : 4;
            if (obs.Payload.Length < rule.Offset + width)
                continue;

            ulong claimed = ReadInt(obs.Payload, rule.Offset, width, rule.Endian);
            var bodyStart = rule.Offset + width;
            var remaining = obs.Payload.Length - bodyStart;
            if (remaining < 0)
                remaining = 0;

            if (type is "lengthprefix" or "claimedexceedspayload")
            {
                var coversSelf = rule.Covers.Equals("self", StringComparison.OrdinalIgnoreCase);
                var expectedBody = coversSelf
                    ? (claimed > (ulong)(rule.Offset + width) ? claimed - (ulong)(rule.Offset + width) : 0UL)
                    : claimed;

                // Semantic overflow: claimed length wraps / exceeds payload / exceeds plausible ceiling.
                var exceeds = expectedBody > (ulong)remaining;
                var absurd = rule.MaxPlausible is int max && claimed > (ulong)max;
                // Classic wrap: offset + claimed overflows 32-bit space
                var wrap = width == 4 && claimed > int.MaxValue;

                if ((exceeds || absurd || wrap) && LooksAccepted(obs.Result))
                {
                    findings.Add(MakeFinding(obs, id, "IntegerRule", sev, 0.85,
                        "length field consistent with payload / plausible bounds",
                        $"claimed={claimed} remaining={remaining} exceeds={exceeds} absurd={absurd} wrap={wrap}",
                        $"{{\"claimed\":{claimed},\"remaining\":{remaining},\"payload_len\":{obs.Payload.Length}}}",
                        "integer.lengthPrefix"));
                }
                else if ((exceeds || absurd || wrap) && !obs.Result.Crashed)
                {
                    findings.Add(MakeFinding(obs, id, "IntegerRule", "nearMiss", 0.5,
                        "length field consistent (rejected or ignored is OK)",
                        $"claimed={claimed} remaining={remaining}",
                        $"{{\"claimed\":{claimed},\"remaining\":{remaining}}}",
                        "integer.lengthPrefix"));
                }
            }
        }
    }

    private static void EvaluateStructure(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        foreach (var rule in cfg.Structure)
        {
            if (!CommandMatches(obs.CommandName, rule.WhenCommand))
                continue;
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "structure") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "nearMiss" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();
            var accepted = LooksAccepted(obs.Result);
            if (rule.OnlyWhenAccepted && !accepted)
                continue;

            var bad = false;
            var expected = "";
            var actual = "";
            switch (type)
            {
                case "minsize":
                    expected = $"payload ≥ {rule.Bytes} bytes";
                    actual = $"len={obs.Payload.Length}";
                    bad = rule.Bytes is int min && obs.Payload.Length < min;
                    break;
                case "maxsize":
                    expected = $"payload ≤ {rule.Bytes} bytes";
                    actual = $"len={obs.Payload.Length}";
                    bad = rule.Bytes is int max && obs.Payload.Length > max;
                    break;
                case "requireprefix":
                    expected = $"prefix '{rule.Prefix}'";
                    actual = Truncate(Encoding.ASCII.GetString(obs.Payload.AsSpan(0, Math.Min(32, obs.Payload.Length))), 40);
                    bad = !string.IsNullOrEmpty(rule.Prefix) &&
                          !Encoding.ASCII.GetString(obs.Payload).StartsWith(rule.Prefix, StringComparison.Ordinal);
                    break;
                case "requiremagichex" or "requireprefixhex":
                {
                    expected = $"magic hex {rule.Hex}";
                    try
                    {
                        var magic = Convert.FromHexString((rule.Hex ?? "").Replace(" ", "").Replace("-", ""));
                        actual = Convert.ToHexString(obs.Payload.AsSpan(0, Math.Min(magic.Length, obs.Payload.Length)));
                        bad = obs.Payload.Length < magic.Length ||
                              !obs.Payload.AsSpan(0, magic.Length).SequenceEqual(magic);
                    }
                    catch
                    {
                        bad = false;
                    }
                    break;
                }
            }

            if (bad)
            {
                findings.Add(MakeFinding(obs, id, "StructureRule",
                    accepted ? (sev == "nearMiss" ? "violation" : sev) : sev,
                    accepted ? 0.8 : 0.5,
                    expected, actual,
                    $"{{\"payload_len\":{obs.Payload.Length},\"accepted\":{accepted.ToString().ToLowerInvariant()}}}",
                    "structure"));
            }
        }
    }

    private static void EvaluateResource(
        OracleObservation obs,
        OracleConfig cfg,
        List<OracleFindingDto> findings)
    {
        foreach (var rule in cfg.Resource)
        {
            if (!CommandMatches(obs.CommandName, rule.WhenCommand))
                continue;
            var id = string.IsNullOrWhiteSpace(rule.Id) ? (rule.Type ?? "resource") : rule.Id;
            var sev = string.IsNullOrWhiteSpace(rule.Severity) ? "violation" : rule.Severity;
            var type = (rule.Type ?? "").Trim().ToLowerInvariant();
            var respLen = obs.Result.ResponseBytes?.Length ?? 0;

            switch (type)
            {
                case "maxresponsebytes":
                    if (rule.MaxBytes is int mr && respLen > mr)
                    {
                        findings.Add(MakeFinding(obs, id, "ResourceRule", sev, 0.8,
                            $"response ≤ {mr} bytes", $"response_len={respLen}",
                            NormalizeObservation(obs.Result), "resource.maxResponse"));
                    }
                    break;
                case "maxpayloadbytes":
                    if (rule.MaxBytes is int mp && obs.Payload.Length > mp && LooksAccepted(obs.Result))
                    {
                        findings.Add(MakeFinding(obs, id, "ResourceRule", sev, 0.75,
                            $"accepted payload ≤ {mp} bytes", $"payload_len={obs.Payload.Length}",
                            NormalizeObservation(obs.Result), "resource.maxPayload"));
                    }
                    break;
                case "responsetopayloadratio":
                    if (rule.MaxRatio is double ratio && ratio > 0 && obs.Payload.Length > 0 &&
                        respLen > ratio * obs.Payload.Length)
                    {
                        findings.Add(MakeFinding(obs, id, "ResourceRule", sev, 0.7,
                            $"response/payload ≤ {ratio}",
                            $"response={respLen} payload={obs.Payload.Length}",
                            NormalizeObservation(obs.Result), "resource.ratio"));
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

    /// <summary>Heuristic: non-crash + non-empty success-ish response (not mismatch Detail).</summary>
    private static bool LooksAccepted(TargetRunResult r)
    {
        if (r.Crashed)
            return false;
        var detail = r.Detail ?? "";
        if (detail.Contains("mismatch", StringComparison.OrdinalIgnoreCase) ||
            detail.Contains("post_receive", StringComparison.OrdinalIgnoreCase))
            return false;
        if (r.ResponseBytes is { Length: > 0 })
            return true;
        return r.ExitCode is null or 0;
    }

    private static ulong ReadInt(byte[] buf, int offset, int width, string endian)
    {
        var be = endian.Equals("be", StringComparison.OrdinalIgnoreCase) ||
                 endian.Equals("big", StringComparison.OrdinalIgnoreCase);
        ulong v = 0;
        if (be)
        {
            for (var i = 0; i < width; i++)
                v = (v << 8) | buf[offset + i];
        }
        else
        {
            for (var i = width - 1; i >= 0; i--)
                v = (v << 8) | buf[offset + i];
        }
        return v;
    }

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
