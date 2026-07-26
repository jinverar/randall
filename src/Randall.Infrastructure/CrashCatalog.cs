using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class CrashCatalog
{
    public static string? FindRepoRoot()
    {
        var starts = new[]
        {
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
        };

        foreach (var start in starts)
        {
            if (string.IsNullOrWhiteSpace(start))
                continue;

            var dir = new DirectoryInfo(Path.GetFullPath(start));
            while (dir is not null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
                    return dir.FullName;
                dir = dir.Parent;
            }
        }

        return null;
    }

    public static IReadOnlyList<CrashSummaryDto> ListAll(string? repoRoot = null, string? projectFilter = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var crashesRoot = Path.Combine(repoRoot, "data", "crashes");
        if (!Directory.Exists(crashesRoot))
            return [];

        var results = new List<CrashSummaryDto>();
        foreach (var dir in Directory.EnumerateDirectories(crashesRoot))
        {
            var projectName = Path.GetFileName(dir);
            if (projectFilter is not null &&
                !projectName.Equals(projectFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            var store = new CrashStore(dir);
            var pageHeapEnabled = TryResolvePageHeapForProject(projectName, repoRoot);
            var projectRows = new List<(CrashSummaryDto Summary, CrashTriageDto Triage, CrashSidecarDto? Sidecar, CrashAnalysisDto? Analysis, CdbTriageDto? Cdb, int InputLength, DebuggerObservation? Debugger)>();
            foreach (var c in store.List())
            {
                var analysisPath = CrashAnalysisWriter.AnalysisPathFor(dir, c.Id);
                var analysis = CrashAnalysisWriter.TryRead(analysisPath);
                var sidecar = CrashSidecarWriter.TryRead(c.SidecarPath);
                var hint = analysis?.ExceptionHint
                    ?? sidecar?.ExceptionHint
                    ?? WindowsExceptionHints.Describe(
                        int.TryParse(c.TargetExitCode, out var ec) ? ec : null);
                var summary = new CrashSummaryDto(
                    c.Id, c.Project, c.Iteration, c.Mutator, c.InputHash, c.InputPath,
                    c.MiniDumpPath, c.TargetExitCode, c.TriageTag, c.SidecarPath, c.RunId, c.At);
                var cdbSidecar = WindowsCdbCrashAnalysisWriter.TryRead(
                    WindowsCdbCrashAnalysisWriter.TriagePathFor(dir, c.Id));
                var debugger = ScreamInvestigator.TryRead(
                    ScreamInvestigator.ObservationPathFor(dir, c.Id));
                var triage = CrashTriage.Classify(
                    analysis, sidecar, summary, null, cdbSidecar?.ExploitableClassification, debugger);
                var staticFn = CrashStaticFunctionMapper.TryMapFromCrash(
                    projectName, analysis, triage, repoRoot);
                if (staticFn is not null)
                    triage = triage with { StaticFunction = staticFn };

                var corruptionChainPreview = CorruptionChainBuilder.TryRead(
                    CorruptionChainBuilder.PathFor(dir, c.Id));
                triage = triage with
                {
                    SemanticFingerprint = SemanticCrashFingerprint.Build(
                        triage.Class,
                        debugger,
                        sidecar,
                        corruptionChainPreview,
                        triage.PatternDepthBytes,
                        triage),
                };

                var inputLength = 0;
                if (File.Exists(c.InputPath))
                {
                    try { inputLength = (int)new FileInfo(c.InputPath).Length; }
                    catch { /* ignore */ }
                }

                var enrichedSummary = new CrashSummaryDto(
                    c.Id,
                    c.Project,
                    c.Iteration,
                    c.Mutator,
                    c.InputHash,
                    c.InputPath,
                    c.MiniDumpPath,
                    c.TargetExitCode,
                    c.TriageTag,
                    c.SidecarPath,
                    c.RunId,
                    c.At,
                    triage.Class,
                    triage.Severity,
                    triage.FaultAddress ?? analysis?.FaultAddress,
                    triage.ExceptionHint ?? hint,
                    triage.ClusterKey,
                    triage.IpLooksControlled,
                    staticFn is not null ? CrashStaticFunctionMapper.FormatOneLine(staticFn) : null,
                    SemanticFingerprint: triage.SemanticFingerprint,
                    SilentScream: sidecar?.SilentScream == true
                        || string.Equals(c.TriageTag, SilentScreamBuilder.TriageTag, StringComparison.OrdinalIgnoreCase)
                        || triage.Class == "oracle_only");

                projectRows.Add((enrichedSummary, triage, sidecar, analysis, MapCdbTriage(cdbSidecar), inputLength, debugger));
            }

            var projectSummaries = projectRows.Select(r => r.Summary).ToList();
            var projectContexts = ScreamEvolutionBuilder.LoadProjectContexts(dir, projectName);
            foreach (var row in projectRows)
            {
                var corruptionChain = CorruptionChainBuilder.TryRead(
                    CorruptionChainBuilder.PathFor(dir, row.Summary.Id));
                var evolution = ScreamEvolutionBuilder.TryRead(
                        ScreamEvolutionBuilder.PathFor(dir, row.Summary.Id))
                    ?? ScreamEvolutionBuilder.Build(
                        row.Summary.Id,
                        projectName,
                        row.Sidecar,
                        row.Triage,
                        row.Debugger,
                        corruptionChain,
                        projectContexts);
                var hypotheses = HypothesisEngine.TryReadForCrash(dir, row.Summary.Id);
                var intelligence = CrashIntelligenceBuilder.Build(
                    row.Summary,
                    row.Triage,
                    row.Sidecar,
                    row.InputLength,
                    projectSummaries,
                    row.Analysis,
                    row.Cdb,
                    pageHeapEnabled,
                    row.Summary.TriageTag,
                    row.Debugger,
                    corruptionChain,
                    evolution,
                    hypotheses);
                var deepScream = DeepScreamBuilder.TryRead(
                        DeepScreamBuilder.PathFor(dir, row.Summary.Id))
                    ?? DeepScreamBuilder.Evaluate(
                        row.Summary.Id,
                        projectName,
                        intelligence.ScreamScore,
                        intelligence.SeenCount,
                        intelligence.Reproducible,
                        intelligence.Minimized,
                        row.Summary.MiniDumpPath,
                        dir);
                results.Add(CrashIntelligenceBuilder.WithListIntelligence(row.Summary, intelligence with
                {
                    DeepScreamCandidate = deepScream.IsCandidate,
                    DeepScreamSummary = DeepScreamBuilder.FormatSummary(deepScream),
                    DeepScreamMinimizedBonus = deepScream.Minimized && deepScream.IsCandidate,
                }));
            }
        }

        return results.OrderByDescending(c => c.ObservedAt).ToList();
    }

    public static IReadOnlyList<CrashClusterDto> ListClusters(string? repoRoot = null, string? projectFilter = null)
    {
        var crashes = ListAll(repoRoot, projectFilter);
        return CrashCluster.Build(crashes, repoRoot)
            .Select(c => new CrashClusterDto(
                c.ClusterId,
                c.Project,
                c.Count,
                c.RepresentativeId,
                c.RepresentativeHash,
                c.RepresentativeMutator,
                c.LengthBucket,
                c.CrashClass,
                c.Severity,
                c.ExceptionHint,
                c.FaultAddress,
                c.SemanticFingerprint))
            .ToList();
    }

    /// <summary>Project bug genealogy (N probable vulns / M failures) — builds if missing.</summary>
    public static BugGenealogyReportDto? GetBugGenealogy(string project, string? repoRoot = null, bool rebuild = false)
    {
        if (string.IsNullOrWhiteSpace(project)) return null;
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null) return null;
        if (!rebuild)
        {
            var existing = BugGenealogyEngine.TryLoad(project, repoRoot);
            if (existing is not null) return existing;
        }

        return BugGenealogyEngine.PersistForProject(project, repoRoot);
    }

    /// <summary>
    /// Per-crash counterfactual report — returns persisted live/plan result when present.
    /// When <paramref name="live"/> is true and a project YAML can be resolved, runs the
    /// bounded execute→observe→persist loop via <see cref="CounterfactualLiveLoop"/>.
    /// </summary>
    public static CounterfactualReportDto? GetCounterfactual(
        Guid crashId,
        string? repoRoot = null,
        bool rebuild = false,
        bool live = false)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null) return null;
        var summary = ListAll(repoRoot).FirstOrDefault(c => c.Id == crashId);
        if (summary is null) return null;
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", summary.Project);
        if (!rebuild && !live)
        {
            var existing = CounterfactualEngine.TryReadForCrash(crashesDir, crashId);
            if (existing is not null) return existing;
        }

        byte[]? bytes = null;
        if (File.Exists(summary.InputPath))
        {
            try { bytes = File.ReadAllBytes(summary.InputPath); }
            catch { /* ignore */ }
        }

        var root = RootCauseEngine.TryRead(RootCauseEngine.PathFor(crashesDir, crashId));
        var influence = InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, crashId));
        var corruption = CorruptionChainBuilder.TryRead(CorruptionChainBuilder.PathFor(crashesDir, crashId));
        var hypotheses = HypothesisEngine.TryReadForCrash(crashesDir, crashId);

        Func<byte[], bool>? stillCrashes = null;
        if (live)
        {
            var yamlPath = TryResolveProjectYaml(summary.Project, repoRoot);
            if (yamlPath is not null)
            {
                try
                {
                    var project = ProjectLoader.Load(yamlPath);
                    stillCrashes = CounterfactualLiveLoop.CreateReplayOracle(project, yamlPath);
                }
                catch
                {
                    stillCrashes = null;
                }
            }
        }

        if (stillCrashes is not null && bytes is { Length: > 0 })
        {
            return CounterfactualLiveLoop.PersistOrRunLive(
                crashesDir, crashId, summary.Project, bytes, stillCrashes,
                maxProbes: CounterfactualLiveLoop.DefaultMaxProbes,
                settleSkeptic: true,
                force: rebuild || live,
                influence: influence,
                rootCause: root,
                corruption: corruption,
                hypotheses: hypotheses).Report;
        }

        return CounterfactualEngine.PersistForCrash(
            crashesDir, crashId, summary.Project, bytes,
            stillCrashes: null,
            influence: influence,
            rootCause: root,
            corruption: corruption);
    }

    /// <summary>Best-effort resolve of <c>projects/&lt;name&gt;.yaml</c> under the repo root.</summary>
    public static string? TryResolveProjectYaml(string project, string? repoRoot = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null || string.IsNullOrWhiteSpace(project))
            return null;
        foreach (var candidate in new[]
                 {
                     Path.Combine(repoRoot, "projects", project + ".yaml"),
                     Path.Combine(repoRoot, "projects", project + ".yml"),
                     Path.Combine(repoRoot, "projects", "local", project + ".yaml"),
                 })
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>Per-crash vulnerability twins — rebuilds from root cause + optional Ghidra map.</summary>
    public static VulnerabilityTwinReportDto? GetVulnerabilityTwins(Guid crashId, string? repoRoot = null, bool rebuild = false)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null) return null;
        var summary = ListAll(repoRoot).FirstOrDefault(c => c.Id == crashId);
        if (summary is null) return null;
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", summary.Project);
        if (!rebuild)
        {
            var existing = VulnerabilityTwinEngine.TryReadForCrash(crashesDir, crashId);
            if (existing is not null) return existing;
        }

        var root = RootCauseEngine.TryRead(RootCauseEngine.PathFor(crashesDir, crashId));
        var debugger = ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(crashesDir, crashId));
        var sidecar = CrashSidecarWriter.TryRead(summary.SidecarPath);
        var analysis = CrashAnalysisWriter.TryRead(CrashAnalysisWriter.AnalysisPathFor(crashesDir, crashId));
        var triage = CrashTriage.Classify(analysis, sidecar, summary, null, debugger: debugger);
        return VulnerabilityTwinEngine.PersistForCrash(
            crashesDir, crashId, summary.Project, root, triage, debugger, repoRoot, queueHuntHints: true);
    }

    /// <summary>First non-empty dump path on the crash record (summary, analysis, sidecar).</summary>
    public static string? ResolveDumpPath(CrashDetailDto detail)
    {
        foreach (var candidate in new[]
                 {
                     detail.Summary.MiniDumpPath,
                     detail.Analysis?.DumpPath,
                     detail.Sidecar?.MiniDumpPath,
                 })
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            try
            {
                if (File.Exists(candidate) && new FileInfo(candidate).Length > 0)
                    return candidate;
            }
            catch
            {
                /* ignore */
            }
        }

        return null;
    }

    public static CrashDetailDto? GetDetail(Guid id, string? repoRoot = null)
    {
        foreach (var summary in ListAll(repoRoot))
        {
            if (summary.Id != id)
                continue;
            if (!File.Exists(summary.InputPath))
            {
                var missingTriage = CrashTriage.Classify(null, null, summary);
                return new CrashDetailDto(summary, 0, "(file missing)", "(file missing)", null, null, missingTriage);
            }

            var bytes = File.ReadAllBytes(summary.InputPath);
            var previewLen = Math.Min(bytes.Length, 256);
            var hex = string.Join(' ', bytes.AsSpan(0, previewLen).ToArray().Select(b => b.ToString("X2")));
            if (bytes.Length > previewLen)
                hex += " …";
            var ascii = BuildAsciiPreview(bytes, previewLen);
            var sidecar = CrashSidecarWriter.TryRead(summary.SidecarPath);
            var crashesDir = Path.GetDirectoryName(summary.InputPath)!;
            var analysisPath = CrashAnalysisWriter.AnalysisPathFor(crashesDir, summary.Id);
            var analysis = CrashAnalysisWriter.TryRead(analysisPath)
                ?? (summary.MiniDumpPath is not null
                    ? CrashAnalysisWriter.AnalyzeDump(summary.MiniDumpPath)
                    : null);
            var cdbSidecar = WindowsCdbCrashAnalysisWriter.TryRead(
                WindowsCdbCrashAnalysisWriter.TriagePathFor(crashesDir, summary.Id));
            var debugger = ScreamInvestigator.TryRead(
                ScreamInvestigator.ObservationPathFor(crashesDir, summary.Id));
            var triage = CrashTriage.Classify(
                analysis, sidecar, summary, bytes, cdbSidecar?.ExploitableClassification, debugger);
            var staticFn = CrashStaticFunctionMapper.TryMapFromCrash(
                summary.Project, analysis, triage, repoRoot);
            if (staticFn is not null)
                triage = triage with { StaticFunction = staticFn };
            var cdbTriage = MapCdbTriage(cdbSidecar);
            var corruptionChain = CorruptionChainBuilder.TryRead(
                CorruptionChainBuilder.PathFor(crashesDir, summary.Id));
            triage = triage with
            {
                SemanticFingerprint = SemanticCrashFingerprint.Build(
                    triage.Class,
                    debugger,
                    sidecar,
                    corruptionChain,
                    triage.PatternDepthBytes,
                    triage),
            };
            var projectContexts = ScreamEvolutionBuilder.LoadProjectContexts(crashesDir, summary.Project);
            var evolution = ScreamEvolutionBuilder.TryRead(
                    ScreamEvolutionBuilder.PathFor(crashesDir, summary.Id))
                ?? ScreamEvolutionBuilder.Build(
                    summary.Id,
                    summary.Project,
                    sidecar,
                    triage,
                    debugger,
                    corruptionChain,
                    projectContexts);
            var hypotheses = HypothesisEngine.TryReadForCrash(crashesDir, summary.Id);
            var backwardTrace = BackwardTraceBuilder.TryRead(
                    BackwardTraceBuilder.PathFor(crashesDir, summary.Id))
                ?? BackwardTraceBuilder.Build(
                    summary.Id,
                    summary.Project,
                    sidecar,
                    debugger,
                    triage,
                    corruptionChain,
                    bytes);
            var rootCauseFacts = EvidenceFactBuilder.CollectFacts(
                summary.Id,
                summary.Project,
                sidecar,
                triage,
                debugger,
                corruptionChain,
                backwardTrace,
                evolution,
                sidecar?.RandallScore,
                hypotheses);
            var influenceMap = InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, summary.Id))
                ?? InfluenceEngine.Build(
                    summary.Id,
                    summary.Project,
                    sidecar,
                    triage,
                    debugger,
                    corruptionChain,
                    backwardTrace,
                    hypotheses,
                    rootCauseFacts,
                    bytes);
            var rootCause = RootCauseEngine.TryRead(
                    RootCauseEngine.PathFor(crashesDir, summary.Id))
                ?? RootCauseEngine.Build(
                    summary.Id,
                    summary.Project,
                    sidecar,
                    triage,
                    debugger,
                    corruptionChain,
                    backwardTrace,
                    sidecar?.RandallScore);
            var pageHeapEnabled = TryResolvePageHeap(sidecar, repoRoot);
            var projectSummaries = ListAll(repoRoot).Where(x => x.Project == summary.Project).ToList();
            var evidence = EvidenceFactBuilder.TryReadForCrash(crashesDir, summary.Id)
                ?? EvidenceFactBuilder.Build(
                    summary.Id,
                    summary.Project,
                    sidecar,
                    triage,
                    debugger,
                    corruptionChain,
                    backwardTrace,
                    evolution,
                    sidecar?.RandallScore,
                    hypotheses,
                    analysis,
                    cdbTriage,
                    pageHeapEnabled,
                    summary.TriageTag);
            var primitives = PrimitiveEngine.TryReadForCrash(crashesDir, summary.Id)
                ?? PrimitiveEngine.Build(
                    summary.Id,
                    summary.Project,
                    influenceMap,
                    rootCause,
                    debugger,
                    corruptionChain,
                    triage,
                    evidence.Facts,
                    hypotheses);
            var skeptic = SkepticEngine.TryReadForCrash(crashesDir, summary.Id);
            var advisor = ExploitabilityAdvisor.TryReadForCrash(crashesDir, summary.Id)
                ?? ExploitabilityAdvisor.Build(
                    summary.Id,
                    summary.Project,
                    rootCause,
                    influenceMap,
                    primitives,
                    debugger,
                    triage,
                    skeptic);
            var intelligence = CrashIntelligenceBuilder.Build(
                summary,
                triage,
                sidecar,
                bytes.Length,
                projectSummaries,
                analysis,
                cdbTriage,
                pageHeapEnabled,
                summary.TriageTag,
                debugger,
                corruptionChain,
                evolution,
                hypotheses,
                rootCause,
                evidence.Facts,
                primitives,
                advisor);
            var deepScream = DeepScreamBuilder.TryRead(
                    DeepScreamBuilder.PathFor(crashesDir, summary.Id))
                ?? DeepScreamBuilder.Evaluate(
                    summary.Id,
                    summary.Project,
                    intelligence.ScreamScore,
                    intelligence.SeenCount,
                    intelligence.Reproducible,
                    intelligence.Minimized,
                    summary.MiniDumpPath,
                    crashesDir);
            intelligence = intelligence with
            {
                DeepScreamCandidate = deepScream.IsCandidate,
                DeepScreamSummary = DeepScreamBuilder.FormatSummary(deepScream),
                DeepScreamMinimizedBonus = deepScream.Minimized && deepScream.IsCandidate,
            };
            return new CrashDetailDto(
                CrashIntelligenceBuilder.WithListIntelligence(summary, intelligence),
                bytes.Length,
                hex,
                ascii,
                sidecar,
                analysis,
                triage,
                cdbTriage,
                intelligence,
                debugger,
                corruptionChain,
                evolution,
                hypotheses,
                deepScream,
                backwardTrace,
                rootCause,
                influenceMap,
                evidence);
        }
        return null;
    }

    internal static CdbTriageDto? MapCdbTriage(WindowsCdbCrashAnalysisWriter.CdbTriageSidecar? s) =>
        s is null
            ? null
            : new CdbTriageDto(
                s.Ok,
                s.ExploitableClassification,
                s.ExploitableDescription,
                s.AnalyzeTextPath,
                s.ExploitableTextPath,
                s.TriageJsonPath,
                s.MsecAvailable,
                s.Error);

    private static bool TryResolvePageHeap(CrashSidecarDto? sidecar, string? repoRoot)
    {
        if (sidecar?.FuzzSnapshot.ConfigPath is not { } cfgPath)
            return false;
        return TryLoadPageHeap(cfgPath, repoRoot);
    }

    private static bool TryResolvePageHeapForProject(string projectName, string? repoRoot)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return false;

        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                if (string.Equals(p.Name, projectName, StringComparison.OrdinalIgnoreCase))
                    return p.Target.PageHeap;
            }
            catch
            {
                /* ignore */
            }
        }

        return false;
    }

    private static bool TryLoadPageHeap(string configPath, string? repoRoot)
    {
        try
        {
            var yaml = configPath;
            if (!Path.IsPathRooted(yaml))
            {
                repoRoot ??= FindRepoRoot();
                if (repoRoot is not null)
                    yaml = Path.Combine(repoRoot, configPath.Replace('/', Path.DirectorySeparatorChar));
            }

            if (!File.Exists(yaml))
                return false;

            return ProjectLoader.Load(yaml).Target.PageHeap;
        }
        catch
        {
            return false;
        }
    }

    internal static string BuildAsciiPreview(ReadOnlySpan<byte> bytes, int previewLen)
    {
        var chars = new char[previewLen];
        for (var i = 0; i < previewLen; i++)
        {
            var b = bytes[i];
            chars[i] = b is >= 32 and <= 126 ? (char)b : '.';
        }
        var text = new string(chars);
        if (bytes.Length > previewLen)
            text += " …";
        return text;
    }

    public static IReadOnlyList<TargetProfileDto> ListTargets(string? repoRoot = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var projectsDir = Path.Combine(repoRoot, "projects");
        var list = new List<TargetProfileDto>();
        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                list.Add(new TargetProfileDto(p.Name, p.Kind, p.Description, path));
            }
            catch { /* skip invalid project */ }
        }
        return list;
    }
}

public sealed class ReplayEngine
{
    public async Task<TargetRunResult> ReplayAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        Process? server = null;
        if (ProjectKinds.IsTcpLike(project) && project.Target.LongLived)
            server = TargetRunner.StartTarget(project, yamlPath, null);

        try
        {
            return await TargetRunner.RunPayloadAsync(project, yamlPath, payload, server, cancellationToken);
        }
        finally
        {
            if (server is { HasExited: false })
            {
                server.Kill(entireProcessTree: true);
                server.Dispose();
            }
        }
    }
}
