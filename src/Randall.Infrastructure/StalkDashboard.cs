using System.Diagnostics;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Bug Stalker dashboard payload for the web UI.</summary>
public static class StalkDashboard
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static StalkDashboardDto? ForProject(
        string projectName,
        FuzzSessionStatusDto? fuzzStatus = null,
        Guid? focusCrashId = null,
        string? focusRunId = null)
    {
        var repoRoot = CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;

        var configPath = CrashCatalog.ListTargets(repoRoot)
            .FirstOrDefault(t => t.Name.Equals(projectName, StringComparison.OrdinalIgnoreCase))
            ?.ConfigPath;
        if (configPath is null || !File.Exists(configPath))
            return null;

        var project = ProjectLoader.Load(configPath);
        var graph = SessionGraphValidator.Validate(project, configPath);
        var corpus = CorpusStats.ForProject(project.Name, repoRoot);
        var exePath = string.IsNullOrWhiteSpace(project.Target.Executable)
            ? null
            : ProjectLoader.ResolvePath(configPath, project.Target.Executable);
        var targetName = exePath is not null ? Path.GetFileName(exePath) : project.Name;
        var arch = DetectArch(exePath);
        var pid = fuzzStatus?.TargetPid ?? FindPid(exePath, targetName);

        var opened = FuzzSessionArchive.GetOpenState(repoRoot);
        var effectiveRunId = !string.IsNullOrWhiteSpace(focusRunId)
            ? focusRunId
            : opened.RunId is not null
              && opened.Project is not null
              && opened.Project.Equals(project.Name, StringComparison.OrdinalIgnoreCase)
                ? opened.RunId
                : null;

        string? crashListWarning = null;
        IReadOnlyList<CrashSummaryDto> crashes;
        try
        {
            crashes = CrashCatalog.ListAll(repoRoot, project.Name);
        }
        catch (Exception ex)
        {
            crashes = [];
            crashListWarning = $"Crash catalog partially unavailable: {ex.Message}";
            Console.Error.WriteLine($"[StalkDashboard] warn: ListAll({project.Name}): {ex.Message}");
        }

        var focusCrash = focusCrashId is Guid fid
            ? crashes.FirstOrDefault(c => c.Id == fid)
            : null;
        var latestCrash = focusCrash ?? crashes.FirstOrDefault();
        // Lite only — full GetDetail re-lists/enriches the whole project and hangs the live UI.
        CrashDetailDto? latestDetail = null;
        if (latestCrash is not null)
        {
            try { latestDetail = CrashCatalog.GetDetailLite(latestCrash.Id, repoRoot); }
            catch (Exception ex)
            {
                crashListWarning ??= $"Crash detail unavailable: {ex.Message}";
                Console.Error.WriteLine($"[StalkDashboard] warn: GetDetailLite: {ex.Message}");
            }
        }

        var run = !string.IsNullOrWhiteSpace(effectiveRunId)
            ? FuzzSessionArchive.LoadManifest(effectiveRunId, repoRoot)
              ?? FindLatestRun(project, configPath, fuzzStatus)
            : FindLatestRun(project, configPath, fuzzStatus);
        // Merge live counters into the graph spine when journal is still catching up.
        run = OverlayLiveRunCounters(run, fuzzStatus, configPath);
        var liveForProject = fuzzStatus is not null
            && (fuzzStatus.Running || fuzzStatus.Phase is "starting" or "running" or "stopping")
            && PathsMatch(fuzzStatus.ConfigPath, configPath);
        // Live fuzz must see all project crashes on the timeline (RunId on disk may lag
        // or point at a prior journal while scream harvest already has new canisters).
        var timeline = BuildTimeline(run, latestDetail, crashes, liveForProject);
        var crashEdges = focusCrashId is not null && latestDetail is not null
            ? LoadCrashCoverageEdges(latestDetail, repoRoot)
            : Array.Empty<string>();
        var usedCrashCoverage = false;
        var missingCrashCoverage = focusCrashId is not null && crashEdges.Count == 0;
        List<StalkBlockDto> blocks;
        List<StalkEdgeDto> edges;
        if (crashEdges.Count > 0 && focusCrashId is not null && latestDetail is not null)
        {
            var covGraph = BuildCrashCoverageGraph(latestDetail, crashEdges, repoRoot);
            blocks = covGraph.Blocks;
            edges = covGraph.Edges;
            usedCrashCoverage = true;
        }
        else if (missingCrashCoverage && latestDetail is not null)
        {
            (blocks, edges) = BuildMissingCrashCoverageGraph(latestDetail);
        }
        else
        {
            (blocks, edges) = BuildGraph(project, graph, latestDetail, run, crashes, liveForProject);
        }

        var hotBlocks = usedCrashCoverage
            ? crashEdges.Take(8).Select(e => new StalkHotBlockDto(ShortEdge(e), 1)).ToList()
            : (run?.HotEdges ?? [])
                .Take(8)
                .Select(h => new StalkHotBlockDto(ShortEdge(h.Edge), h.HitCount))
                .ToList();

        var crashLog = BuildCrashLog(crashes, repoRoot);
        var status = focusCrash is not null
            ? $"Inspecting {ShortCrashId(focusCrash.Id)}"
            : !string.IsNullOrWhiteSpace(effectiveRunId)
                ? $"Opened {ShortRunId(effectiveRunId)}"
                : ResolveStatus(fuzzStatus, configPath, latestCrash, pid, run);
        var mode = usedCrashCoverage
            ? "Crash BB path"
            : missingCrashCoverage
                ? "No crash coverage"
                : corpus.CoverageEdges > 0 || (run?.HotEdges?.Count > 0) == true
                    ? "Basic Block"
                    : liveForProject
                        ? (graph.HasGraph ? "Live session" : "Live novelty")
                        : project.Fuzz.CoverageGuided || fuzzStatus?.CoverageGuided == true
                            ? "Basic Block"
                            : graph.HasGraph ? "Session Graph" : "Mutation";

        var notes = BuildNotes(status, latestDetail, corpus, graph, hotBlocks, usedCrashCoverage, missingCrashCoverage);
        AppendCoverageHonestyNotes(notes, corpus, fuzzStatus, run, usedCrashCoverage, missingCrashCoverage, liveForProject);
        if (!string.IsNullOrWhiteSpace(crashListWarning))
            notes.Insert(0, crashListWarning);
        if (!string.IsNullOrWhiteSpace(effectiveRunId) && focusCrash is null)
        {
            notes.Insert(0,
                $"Opened fuzz session {effectiveRunId} — Close session to return to live/latest.");
        }
        if (focusCrash is not null)
        {
            notes.Insert(0,
                $"Inspecting crash {ShortCrashId(focusCrash.Id)} (iteration {focusCrash.Iteration}) — Follow live to resume.");
            if (!usedCrashCoverage)
            {
                notes.Insert(1,
                    "No BB coverage trace for this crash — diagram shows a clear empty path. Re-fuzz with coverage-guided + DynamoRIO (or import a stalk layer from this crash) to populate hit blocks.");
            }
            else
            {
                notes.Insert(1,
                    $"Diagram shows {crashEdges.Count} BB edges from this crash's drcov/trace (novel blocks highlighted vs baseline).");
            }
        }
        var exception = latestDetail?.Analysis?.ExceptionHint
            ?? latestDetail?.Sidecar?.ExceptionHint
            ?? latestCrash?.TargetExitCode
            ?? "—";
        var crashAddr = FormatCrashNodeAddress(
            latestDetail,
            latestDetail?.Analysis?.FaultAddress ?? latestCrash?.FaultAddress,
            exception);

        var pathBlocks = blocks.Where(b => b.Id is not "__entry" and not "__crash_site").ToList();
        var hitPath = pathBlocks.Count(b => b.Kind is "hit" or "novel" or "crash" || b.OnCrashPath);
        var totalPath = Math.Max(pathBlocks.Count, 1);
        var (coveragePct, coverageLabel, coverageDetail) = BuildCoverageSummary(
            corpus.CoverageEdges,
            hitPath,
            totalPath,
            mode,
            corpus.DynamoRioAvailable);

        // Path comparison: only real BB edges. Without coverage backend, Diff is N/A (not fake +1).
        var hasBbEdges = corpus.CoverageEdges > 0 || (usedCrashCoverage && crashEdges.Count > 0);
        int currentBlocks;
        int baselineBlocks;
        int diff;
        if (!hasBbEdges)
        {
            currentBlocks = 0;
            baselineBlocks = 0;
            diff = 0;
        }
        else
        {
            currentBlocks = usedCrashCoverage
                ? crashEdges.Count
                : corpus.CoverageEdges;
            var hotNovel = Math.Max(0, (int)(run?.HotEdges?.Sum(h => h.HitCount > 0 ? 1 : 0) ?? 0));
            baselineBlocks = usedCrashCoverage
                ? Math.Max(0, currentBlocks - blocks.Count(b => b.Kind is "novel"))
                : Math.Max(0, currentBlocks - hotNovel);
            if (baselineBlocks > currentBlocks)
                baselineBlocks = currentBlocks;
            diff = currentBlocks - baselineBlocks;
        }

        var firstDiv = blocks.FirstOrDefault(b => b.OnCrashPath && b.Kind is "novel" or "crash")?.Label
            ?? blocks.FirstOrDefault(b => b.Kind is "novel" or "crash")?.Label
            ?? graph.Mutate
            ?? "—";

        // Prefer completed-run / disk stats so end-of-fuzz does not wipe the dashboard.
        var iterations = Math.Max(fuzzStatus?.Iterations ?? 0, run?.Iterations ?? 0);
        var coverageEdges = Math.Max(
            Math.Max(fuzzStatus?.CoverageEdges ?? 0, corpus.CoverageEdges),
            usedCrashCoverage ? crashEdges.Count : 0);
        var (covPct, covLabel, covDetail) = usedCrashCoverage
            ? (Math.Clamp(Math.Round(100.0 * crashEdges.Count / Math.Max(crashEdges.Count + 32, 64), 1), 0.1, 99.9),
                "Crash BB edges",
                $"{crashEdges.Count} edges on selected crash path · session corpus {corpus.CoverageEdges}")
            : (coveragePct, coverageLabel, coverageDetail);

        return new StalkDashboardDto(
            project.Name,
            project.Kind,
            project.Description,
            configPath,
            targetName,
            pid,
            arch,
            mode,
            status,
            fuzzStatus?.Running == true && PathsMatch(fuzzStatus.ConfigPath, configPath),
            iterations,
            Math.Max(fuzzStatus?.Crashes ?? 0, crashes.Count),
            coverageEdges,
            Math.Max(fuzzStatus?.CorpusAdded ?? 0, corpus.SeenInputs),
            covPct,
            covLabel,
            covDetail,
            run?.RunId,
            run?.StartedAt,
            latestCrash is null ? null : Path.GetFileName(latestCrash.InputPath),
            latestCrash?.ObservedAt.ToString("HH:mm:ss.fff"),
            exception,
            crashAddr,
            latestDetail?.Analysis?.Registers?.Rsp is null ? null : "main",
            latestCrash is null ? null : latestCrash.Id.ToString("D"),
            crashLog.FirstOrDefault(c => latestCrash is not null && c.Id == latestCrash.Id)?.Hits
                ?? (latestCrash is null ? 0 : 1),
            EstimateDistance(blocks, latestDetail),
            firstDiv,
            "Last completed corpus frontier",
            baselineBlocks,
            currentBlocks,
            diff,
            blocks,
            edges,
            hotBlocks,
            timeline,
            crashLog,
            notes,
            string.IsNullOrWhiteSpace(graph.Mermaid) ? null : graph.Mermaid,
            corpus.DynamoRioAvailable);
    }

    private static string ResolveStatus(
        FuzzSessionStatusDto? fuzzStatus,
        string configPath,
        CrashSummaryDto? latestCrash,
        int? pid,
        FuzzRunManifestDto? run = null)
    {
        if (fuzzStatus is not null
            && (fuzzStatus.Running || fuzzStatus.Phase is "starting" or "running" or "stopping")
            && PathsMatch(fuzzStatus.ConfigPath, configPath))
        {
            if (fuzzStatus.LastMessage?.Contains("CRASH", StringComparison.OrdinalIgnoreCase) == true)
                return "Crash Detected";
            var phase = (fuzzStatus.Phase ?? "").ToLowerInvariant();
            if (phase == "stopping")
                return "Stopping";
            // Promote out of Starting once iterations flow or phase flips to running.
            if (phase == "starting" && fuzzStatus.Iterations <= 0)
                return "Starting";
            return "Tracing";
        }

        if (fuzzStatus is not null
            && PathsMatch(fuzzStatus.ConfigPath, configPath)
            && fuzzStatus.Phase is "completed" or "stopped")
        {
            return fuzzStatus.Phase.Equals("completed", StringComparison.OrdinalIgnoreCase)
                ? "Completed"
                : "Stopped";
        }

        if (run is { Iterations: > 0 })
            return run.CompletedAt is not null ? "Completed" : "Journaled";

        if (latestCrash is not null && (DateTimeOffset.UtcNow - latestCrash.ObservedAt).TotalHours < 24)
            return "Crash Detected";
        if (pid is not null)
            return "Attached";
        return "Idle";
    }

    private static bool PathsMatch(string? a, string b) =>
        !string.IsNullOrWhiteSpace(a) &&
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

    private static (List<StalkBlockDto> Blocks, List<StalkEdgeDto> Edges) BuildGraph(
        ProjectConfig project,
        SessionGraphReportDto graph,
        CrashDetailDto? latestDetail,
        FuzzRunManifestDto? run,
        IReadOnlyList<CrashSummaryDto>? crashes = null,
        bool liveForProject = false)
    {
        var crashAddr = latestDetail?.Analysis?.FaultAddress;
        var exception = latestDetail?.Analysis?.ExceptionHint
            ?? latestDetail?.Sidecar?.ExceptionHint
            ?? latestDetail?.Summary.TargetExitCode
            ?? "ACCESS_VIOLATION";
        var crashCmd = ResolveCrashCommand(project, graph, latestDetail);
        var path = BuildCrashPath(project, graph, crashCmd);
        var hasCrash = latestDetail is not null;

        if (path.Count == 0 && graph.Commands.Count == 0 && project.SessionCommands.Count == 0)
            return BuildFallbackGraph(run, latestDetail, crashAddr, exception, crashes, liveForProject);

        // Prefer a clear crash spine even when sessionGraph is sparse.
        if (path.Count == 0 && crashCmd is not null)
            path = [crashCmd];
        if (path.Count == 0 && !string.IsNullOrWhiteSpace(graph.Mutate))
            path = string.IsNullOrWhiteSpace(graph.Start) || graph.Start!.Equals(graph.Mutate, StringComparison.OrdinalIgnoreCase)
                ? [graph.Mutate!]
                : [graph.Start!, graph.Mutate!];
        if (path.Count == 0 && !string.IsNullOrWhiteSpace(graph.Start))
            path = [graph.Start!];

        var commandNames = new List<string>();
        if (!string.IsNullOrWhiteSpace(graph.Start))
            commandNames.Add(graph.Start!);
        foreach (var step in path)
        {
            if (!commandNames.Any(c => c.Equals(step, StringComparison.OrdinalIgnoreCase)))
                commandNames.Add(step);
        }

        foreach (var edge in graph.Edges)
        {
            if (!commandNames.Any(c => c.Equals(edge.From, StringComparison.OrdinalIgnoreCase)))
                commandNames.Add(edge.From);
            if (!commandNames.Any(c => c.Equals(edge.To, StringComparison.OrdinalIgnoreCase)))
                commandNames.Add(edge.To);
        }

        foreach (var cmd in project.SessionCommands.Select(c => c.Name))
        {
            if (!commandNames.Any(c => c.Equals(cmd, StringComparison.OrdinalIgnoreCase)))
                commandNames.Add(cmd);
        }

        var pathSet = new HashSet<string>(path, StringComparer.OrdinalIgnoreCase);
        var targetModule = string.IsNullOrWhiteSpace(project.Target.Executable)
            ? project.Name
            : Path.GetFileName(project.Target.Executable);
        var blocks = new List<StalkBlockDto>
        {
            new(
                "__entry",
                "ENTRY",
                "accept()",
                "hit",
                true,
                false,
                "Target accepts connection / opens input",
                0,
                true,
                Role: "entry",
                Module: targetModule,
                ReHints:
                [
                    "Session root — traffic enters here before command dispatch.",
                    "Compare taken vs dashed forks to see which handlers were reachable.",
                ]),
        };

        for (var i = 0; i < commandNames.Count; i++)
        {
            var cmd = commandNames[i];
            var onPath = pathSet.Contains(cmd);
            var pathIndex = onPath ? path.FindIndex(p => p.Equals(cmd, StringComparison.OrdinalIgnoreCase)) + 1 : -1;
            var isStart = graph.Start is not null && cmd.Equals(graph.Start, StringComparison.OrdinalIgnoreCase);
            var isMutate = (graph.Mutate is not null && cmd.Equals(graph.Mutate, StringComparison.OrdinalIgnoreCase))
                || (crashCmd is not null && cmd.Equals(crashCmd, StringComparison.OrdinalIgnoreCase));
            var kind = onPath
                ? (isMutate && hasCrash ? "novel" : "hit")
                : "unexplored";
            var sc = project.SessionCommands.FirstOrDefault(c =>
                c.Name.Equals(cmd, StringComparison.OrdinalIgnoreCase));
            var role = isMutate ? "handler" : onPath ? "command" : "fork";
            var hints = BuildCommandReHints(cmd, sc, isStart, isMutate, onPath, hasCrash, latestDetail);
            long? hitCount = null;
            if (run?.HotEdges is { Count: > 0 } hot)
            {
                var needle = Sanitize(cmd);
                var match = hot.FirstOrDefault(h =>
                    ShortEdge(h.Edge).Contains(needle, StringComparison.OrdinalIgnoreCase));
                if (match is not null)
                    hitCount = match.HitCount;
            }

            blocks.Add(new StalkBlockDto(
                Sanitize(cmd),
                cmd,
                SyntheticAddress(cmd, i),
                kind,
                isStart,
                isMutate,
                DescribeCommand(cmd, isStart, isMutate, onPath, hasCrash),
                pathIndex,
                onPath,
                Role: role,
                Module: targetModule,
                HitCount: hitCount,
                Command: cmd,
                Prefix: sc?.Prefix,
                Preamble: sc?.Preamble,
                ExpectResponse: sc?.ExpectResponse,
                Model: sc?.Model,
                Mutator: isMutate ? latestDetail?.Summary.Mutator : null,
                CrashId: isMutate && hasCrash ? latestDetail?.Summary.Id : null,
                InputLength: isMutate ? latestDetail?.InputLength : null,
                AsciiPreview: isMutate ? latestDetail?.AsciiPreview : null,
                HexPreview: isMutate ? latestDetail?.HexPreview : null,
                ReHints: hints));
        }

        if (hasCrash)
        {
            var fault = FormatCrashNodeAddress(latestDetail, crashAddr, exception);
            var triage = latestDetail?.Triage;
            var analysis = latestDetail?.Analysis;
            var regs = analysis?.Registers;
            blocks.Add(new StalkBlockDto(
                "__crash_site",
                "CRASH",
                fault,
                "crash",
                false,
                false,
                $"{exception}",
                path.Count + 1,
                true,
                Role: "crash",
                Module: analysis?.FaultModule ?? targetModule,
                ExceptionHint: exception,
                FaultModule: analysis?.FaultModule,
                Rip: regs?.Rip,
                Rsp: regs?.Rsp,
                Rbp: regs?.Rbp,
                Severity: triage?.Severity ?? latestDetail?.Summary.Severity,
                CrashClass: triage?.Class ?? latestDetail?.Summary.CrashClass,
                ClusterKey: triage?.ClusterKey,
                CrashId: latestDetail?.Summary.Id,
                Mutator: latestDetail?.Summary.Mutator,
                InputLength: latestDetail?.InputLength,
                AsciiPreview: latestDetail?.AsciiPreview,
                HexPreview: latestDetail?.HexPreview,
                ReHints: BuildCrashReHints(latestDetail)));
        }

        var edges = new List<StalkEdgeDto>();
        var spineRoot = path.Count > 0 ? Sanitize(path[0]) : null;
        if (spineRoot is not null)
            edges.Add(new StalkEdgeDto("__entry", spineRoot, "session", true, true));
        else if (blocks.Count > 1)
            edges.Add(new StalkEdgeDto("__entry", blocks[1].Id, "session", true, false));

        for (var i = 0; i < path.Count - 1; i++)
        {
            edges.Add(new StalkEdgeDto(
                Sanitize(path[i]),
                Sanitize(path[i + 1]),
                EdgeLabel(project, graph, path[i], path[i + 1]),
                true,
                true));
        }

        if (hasCrash && path.Count > 0)
            edges.Add(new StalkEdgeDto(Sanitize(path[^1]), "__crash_site", "fault", true, true));

        // Forks: session-graph edges and orphan commands hanging off ENTRY.
        foreach (var e in graph.Edges)
        {
            var fromId = Sanitize(e.From);
            var toId = Sanitize(e.To);
            if (edges.Any(x => x.From.Equals(fromId, StringComparison.OrdinalIgnoreCase)
                               && x.To.Equals(toId, StringComparison.OrdinalIgnoreCase)))
                continue;
            var onPath = pathSet.Contains(e.From) && pathSet.Contains(e.To);
            edges.Add(new StalkEdgeDto(fromId, toId, e.When, onPath, onPath));
        }

        foreach (var cmd in commandNames)
        {
            var id = Sanitize(cmd);
            var hasIncoming = edges.Any(e => e.To.Equals(id, StringComparison.OrdinalIgnoreCase));
            if (hasIncoming || (spineRoot is not null && id.Equals(spineRoot, StringComparison.OrdinalIgnoreCase)))
                continue;
            edges.Add(new StalkEdgeDto("__entry", id, "fork", false, false));
        }

        return (blocks, edges);
    }

    private static (List<StalkBlockDto> Blocks, List<StalkEdgeDto> Edges) BuildFallbackGraph(
        FuzzRunManifestDto? run,
        CrashDetailDto? latestDetail,
        string? crashAddr,
        string exception,
        IReadOnlyList<CrashSummaryDto>? crashes = null,
        bool liveForProject = false)
    {
        var blocks = new List<StalkBlockDto>();
        var i = 0;
        foreach (var hot in (run?.HotEdges ?? []).Take(10))
        {
            var addr = ShortEdge(hot.Edge);
            blocks.Add(new StalkBlockDto(
                $"e{i}",
                addr,
                addr,
                "hit",
                i == 0,
                false,
                $"Executed basic block ({hot.HitCount} hits)",
                i,
                true));
            i++;
        }

        if (blocks.Count == 0)
        {
            // Live novelty / session spine — not fake BB addresses.
            var iters = run?.Iterations ?? 0;
            var crashCount = Math.Max(run?.CrashesFound ?? 0, crashes?.Count ?? 0);
            var corpusAdded = 0;
            blocks.Add(new StalkBlockDto(
                "entry", "START", "session", "hit", true, false,
                liveForProject
                    ? (iters > 0 ? $"LIVE tracing ({iters} iters)" : "LIVE — waiting for first iteration")
                    : (iters > 0 ? $"Run started ({iters} iterations)" : "Waiting for live / journaled iterations"),
                0, true,
                Role: "entry",
                ReHints:
                [
                    "Live diagram mode — corpus-novelty spine while DynamoRIO BB edges are unavailable.",
                    "Crash sites hang off CORPUS+ as red nodes; install DynamoRIO for basic-block edges.",
                ]));
            blocks.Add(new StalkBlockDto(
                "novelty", "CORPUS+", "novelty", iters > 0 || crashCount > 0 ? "novel" : "unexplored", false, true,
                iters > 0 || crashCount > 0
                    ? $"Corpus-novelty / session path ({iters} iters, {crashCount} crashes) — not DynamoRIO BB edges"
                    : liveForProject
                        ? "Building live novelty graph… enable DynamoRIO or wait for corpus+/crashes"
                        : "LIVE or idle without BB edges — enable DynamoRIO or fuzz without a busy TCP lab port",
                1, true,
                Role: "handler",
                HitCount: iters > 0 ? iters : null,
                ReHints:
                [
                    "Parent→child novelty is approximate without a coverage backend.",
                    "Frontier growth (corpus+) is the stalk signal on stock labs.",
                ]));

            // Recent crash sites as red nodes off the novelty hub (live diagram).
            var recent = (crashes ?? [])
                .OrderByDescending(c => c.ObservedAt)
                .Take(6)
                .ToList();
            var spineTail = "novelty";
            for (var ci = 0; ci < recent.Count; ci++)
            {
                var c = recent[ci];
                var id = $"crash_{c.Id:N}"[..14];
                var fault = FormatCrashNodeAddress(null, c.FaultAddress, c.ExceptionHint ?? c.TargetExitCode);
                blocks.Add(new StalkBlockDto(
                    id,
                    ShortCrashId(c.Id),
                    fault,
                    "crash",
                    false,
                    false,
                    $"{c.ExceptionHint ?? c.TargetExitCode ?? "CRASH"} · iter #{c.Iteration}",
                    2 + ci,
                    true,
                    Role: "crash",
                    ExceptionHint: c.ExceptionHint ?? c.TargetExitCode,
                    Severity: c.Severity,
                    CrashClass: c.CrashClass,
                    CrashId: c.Id,
                    Mutator: c.Mutator));
                spineTail = id;
            }

            if (recent.Count == 0 && latestDetail is null)
            {
                blocks.Add(new StalkBlockDto(
                    "hint", "DOCTOR", "hint", "unexplored", false, false,
                    "randall doctor → DynamoRIO; for TCP stop Labs / leave Coverage-guided unchecked while :port listens",
                    2, false));
            }
            else if (latestDetail is not null && recent.All(c => c.Id != latestDetail.Summary.Id))
            {
                var fault = FormatCrashNodeAddress(latestDetail, crashAddr, exception);
                blocks.Add(new StalkBlockDto(
                    "__crash_site",
                    "CRASH",
                    fault,
                    "crash",
                    false,
                    false,
                    exception,
                    blocks.Count,
                    true,
                    Role: "crash",
                    CrashId: latestDetail.Summary.Id,
                    ExceptionHint: exception));
            }

            _ = spineTail;
            _ = corpusAdded;
        }
        else if (latestDetail is not null)
        {
            var fault = FormatCrashNodeAddress(latestDetail, crashAddr, exception);
            blocks.Add(new StalkBlockDto(
                "__crash_site",
                "CRASH",
                fault,
                "crash",
                false,
                false,
                exception,
                blocks.Count,
                true,
                ExceptionHint: exception));
        }

        var edges = new List<StalkEdgeDto>();
        // Prefer hub layout: entry → novelty, then novelty → each crash (parent→child novelty).
        var novelty = blocks.FirstOrDefault(b => b.Id == "novelty");
        var crashNodes = blocks.Where(b => b.Kind == "crash").ToList();
        if (novelty is not null && blocks.Any(b => b.Id == "entry"))
        {
            edges.Add(new StalkEdgeDto("entry", "novelty", liveForProject ? "live" : "session", true, true));
            foreach (var c in crashNodes)
                edges.Add(new StalkEdgeDto("novelty", c.Id, "crash", true, true));
            var hint = blocks.FirstOrDefault(b => b.Id == "hint");
            if (hint is not null)
                edges.Add(new StalkEdgeDto("novelty", "hint", "hint", false, false));
        }
        else
        {
            for (var e = 0; e < blocks.Count - 1; e++)
                edges.Add(new StalkEdgeDto(blocks[e].Id, blocks[e + 1].Id, "", true, true));
            // Single-node graphs still need a self-visible spine for the renderer.
            if (edges.Count == 0 && blocks.Count == 1)
                edges.Add(new StalkEdgeDto(blocks[0].Id, blocks[0].Id, "loop", true, true));
        }

        return (blocks, edges);
    }

    private static string? ResolveCrashCommand(
        ProjectConfig project,
        SessionGraphReportDto graph,
        CrashDetailDto? latestDetail)
    {
        var cmd = latestDetail?.Sidecar?.Command?.Trim();
        if (!string.IsNullOrWhiteSpace(cmd))
        {
            // Prefer exact session command match; strip trailing junk.
            var match = project.SessionCommands.FirstOrDefault(c =>
                cmd.Equals(c.Name, StringComparison.OrdinalIgnoreCase) ||
                cmd.StartsWith(c.Name, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
                return match.Name;
            if (graph.Commands.Any(c => c.Equals(cmd, StringComparison.OrdinalIgnoreCase)))
                return cmd;
        }

        if (!string.IsNullOrWhiteSpace(graph.Mutate))
            return graph.Mutate;

        var flow = project.SessionFlows.FirstOrDefault();
        return flow?.Steps.LastOrDefault()
               ?? project.SessionCommands.LastOrDefault()?.Name;
    }

    private static List<string> BuildCrashPath(
        ProjectConfig project,
        SessionGraphReportDto graph,
        string? crashCmd)
    {
        var path = new List<string>();
        if (crashCmd is null)
            return path;

        // Prefer a session flow that ends at the crash command.
        var flow = project.SessionFlows.FirstOrDefault(f =>
            f.Steps.Any(s => s.Equals(crashCmd, StringComparison.OrdinalIgnoreCase)));
        if (flow is not null)
        {
            foreach (var step in flow.Steps)
            {
                path.Add(step);
                if (step.Equals(crashCmd, StringComparison.OrdinalIgnoreCase))
                    break;
            }
            return path;
        }

        // Walk session graph from start toward crash command.
        if (graph.HasGraph && !string.IsNullOrWhiteSpace(graph.Start))
        {
            var walked = WalkTo(graph, graph.Start!, crashCmd);
            if (walked.Count > 0)
                return walked;
        }

        if (!string.IsNullOrWhiteSpace(graph.Start) &&
            !graph.Start!.Equals(crashCmd, StringComparison.OrdinalIgnoreCase))
            path.Add(graph.Start!);
        path.Add(crashCmd);
        return path;
    }

    private static List<string> WalkTo(SessionGraphReportDto graph, string start, string target)
    {
        var queue = new Queue<List<string>>();
        queue.Enqueue([start]);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { start };
        while (queue.Count > 0)
        {
            var path = queue.Dequeue();
            var node = path[^1];
            if (node.Equals(target, StringComparison.OrdinalIgnoreCase))
                return path;
            foreach (var edge in graph.Edges.Where(e => e.From.Equals(node, StringComparison.OrdinalIgnoreCase)))
            {
                if (!seen.Add(edge.To))
                    continue;
                var next = path.ToList();
                next.Add(edge.To);
                queue.Enqueue(next);
            }
        }

        return start.Equals(target, StringComparison.OrdinalIgnoreCase) ? [start] : [];
    }

    private static string EdgeLabel(
        ProjectConfig project,
        SessionGraphReportDto graph,
        string from,
        string to)
    {
        var edge = graph.Edges.FirstOrDefault(e =>
            e.From.Equals(from, StringComparison.OrdinalIgnoreCase) &&
            e.To.Equals(to, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(edge?.When))
            return edge.When;
        return "next";
    }

    private static string DescribeCommand(string cmd, bool isStart, bool isMutate, bool onPath, bool hasCrash)
    {
        if (isStart)
            return "Session start — send command / read banner";
        if (isMutate && hasCrash)
            return "Mutated payload reaches vulnerable handler";
        if (isMutate)
            return "Mutation focus — field-aware fuzzing";
        if (onPath)
            return $"On crash path — execute {cmd}";
        return $"Alternate branch — {cmd} not taken this crash";
    }

    private static IReadOnlyList<string> BuildCommandReHints(
        string cmd,
        SessionCommandConfig? sc,
        bool isStart,
        bool isMutate,
        bool onPath,
        bool hasCrash,
        CrashDetailDto? latestDetail)
    {
        var hints = new List<string>();
        if (isStart)
            hints.Add("Likely banner / auth / setup step before the mutable handler.");
        if (isMutate)
            hints.Add("Mutation focus — prioritize this command in IDA/Ghidra when stalking the crash.");
        if (isMutate && hasCrash)
            hints.Add("This node is the last command before the fault — start RE here.");
        if (!onPath)
            hints.Add("Not on this crash spine — useful for mapping alternate protocol handlers.");
        if (!string.IsNullOrWhiteSpace(sc?.Prefix))
            hints.Add($"Wire prefix `{sc.Prefix.Trim()}` — search the binary for this ASCII/token.");
        if (!string.IsNullOrWhiteSpace(sc?.ExpectResponse))
            hints.Add($"Expects response containing `{sc.ExpectResponse}` — good xref for recv/parse.");
        if (!string.IsNullOrWhiteSpace(sc?.Model))
            hints.Add($"Block model `{sc.Model}` — field-aware mutators patch structured fields.");
        if (isMutate && latestDetail?.Triage?.PatternDepthBytes is int depth)
            hints.Add($"Pattern depth triage: RIP/fault dword appears in input around offset {depth}.");
        if (hints.Count == 0)
            hints.Add($"Protocol step `{cmd}` — inspect dispatch table / strcmp of command name.");
        return hints;
    }

    private static IReadOnlyList<string> BuildCrashReHints(CrashDetailDto? detail)
    {
        var hints = new List<string>();
        var triage = detail?.Triage;
        var analysis = detail?.Analysis;
        if (!string.IsNullOrWhiteSpace(triage?.Summary))
            hints.Add(triage.Summary);
        if (triage?.IpLooksControlled == true)
            hints.Add("IP looks controlled / non-image — high priority for RE (check overwrite depth).");
        if (triage?.StackLooksSmashed == true)
            hints.Add("Stack smash signals — inspect saved RIP/SEH and frame cookies.");
        if (triage?.PatternDepthBytes is int depth)
            hints.Add($"Input depth: register/fault pattern at offset {depth} — how deep the buffer got.");
        if (!string.IsNullOrWhiteSpace(analysis?.FaultModule))
            hints.Add($"Fault module `{analysis.FaultModule}` — load this in the debugger first.");
        if (!string.IsNullOrWhiteSpace(analysis?.FaultAddress))
            hints.Add($"Fault VA `{analysis.FaultAddress}` — set BP / go to address in WinDbg / IDA.");
        if (!string.IsNullOrWhiteSpace(detail?.Summary.MiniDumpPath))
            hints.Add("Minidump available — open WinDbg from the Crashes investigation pane.");
        if (hints.Count == 0)
            hints.Add("Crash site — export triage bundle and compare registers against the payload.");
        return hints;
    }

    /// <summary>
    /// Timeline bar strip for the Dashboard (last ≤200 points). Exposed for tests —
    /// crash markers must appear even when the journal is missing (live overlay).
    /// </summary>
    public static IReadOnlyList<StalkTimelinePointDto> BuildTimelineSnapshot(
        FuzzRunManifestDto? run,
        CrashDetailDto? latestDetail,
        IReadOnlyList<CrashSummaryDto> crashes,
        bool liveForProject = false)
        => BuildTimeline(run, latestDetail, crashes, liveForProject);

    private static List<StalkTimelinePointDto> BuildTimeline(
        FuzzRunManifestDto? run,
        CrashDetailDto? latestDetail,
        IReadOnlyList<CrashSummaryDto> crashes,
        bool liveForProject = false)
    {
        var runId = run?.RunId;
        var isLiveOverlay = liveForProject
            || string.Equals(runId, "live", StringComparison.OrdinalIgnoreCase);

        // Prefer crashes from the active run, then newest observation for that iteration.
        // Live overlay / live fuzz has no trustworthy runId match — use the whole project list.
        var scopedCrashes = crashes
            .Where(c =>
                isLiveOverlay
                || string.IsNullOrWhiteSpace(runId)
                || string.Equals(c.RunId, runId, StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(c.RunId))
            .ToList();

        var crashByIteration = scopedCrashes
            .GroupBy(c => c.Iteration)
            .ToDictionary(
                g => g.Key,
                g => g
                    .OrderByDescending(c =>
                        !string.IsNullOrWhiteSpace(runId)
                        && !isLiveOverlay
                        && string.Equals(c.RunId, runId, StringComparison.OrdinalIgnoreCase))
                    .ThenByDescending(c => c.ObservedAt)
                    .First());

        Guid? CrashIdFor(int iteration, bool crashed, string? command = null)
        {
            if (!crashed) return null;
            if (crashByIteration.TryGetValue(iteration, out var hit))
                return hit.Id;

            // Fallback: nearest crash in the same run (iteration numbers can drift).
            var pool = scopedCrashes.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(command))
            {
                var cmdKey = command.Split('/')[0];
                var byCommand = pool
                    .Where(c =>
                        (!string.IsNullOrWhiteSpace(cmdKey)
                            && c.InputPath?.Contains(cmdKey, StringComparison.OrdinalIgnoreCase) == true)
                        || string.Equals(c.Mutator, command, StringComparison.OrdinalIgnoreCase))
                    .OrderBy(c => Math.Abs(c.Iteration - iteration))
                    .ThenByDescending(c => c.ObservedAt)
                    .FirstOrDefault();
                if (byCommand is not null) return byCommand.Id;
            }

            var nearest = pool
                .OrderBy(c => Math.Abs(c.Iteration - iteration))
                .ThenByDescending(c => c.ObservedAt)
                .FirstOrDefault();
            return nearest?.Id ?? latestDetail?.Summary.Id;
        }

        var points = new List<StalkTimelinePointDto>();
        if (run is null)
        {
            for (var i = 0; i < 40; i++)
                points.Add(new StalkTimelinePointDto(i, i % 7 == 0 ? "novel" : "hit", $"bb_{i}", i, false, i % 7 == 0 ? 1 : 0));
            // Place every known crash as a distinct toxic bar (not a single trailing marker).
            var idx = points.Count;
            foreach (var c in scopedCrashes.OrderBy(c => c.Iteration).TakeLast(40))
            {
                points.Add(new StalkTimelinePointDto(
                    idx++,
                    "crash",
                    c.Mutator ?? "CRASH",
                    c.Iteration,
                    true,
                    0,
                    c.Id));
            }
            if (points.Count == 40 && latestDetail is not null)
            {
                points.Add(new StalkTimelinePointDto(
                    40,
                    "crash",
                    "CRASH",
                    latestDetail.Summary.Iteration,
                    true,
                    latestDetail.Sidecar?.NewEdgesAtCrash ?? 0,
                    latestDetail.Summary.Id));
            }
            return points.TakeLast(200).ToList();
        }

        // "live" overlay has no journal dir — also try latest on-disk run for this project.
        var runDir = isLiveOverlay ? null : FindRunDirectory(run.RunId);
        if (runDir is null && !string.IsNullOrWhiteSpace(run.Project))
            runDir = FindLatestRunDirectoryForProject(run.Project);
        var iterPath = runDir is null ? null : Path.Combine(runDir, "iterations.jsonl");
        if (iterPath is null || !File.Exists(iterPath))
        {
            // Synthetic window over the last ≤200 iterations, with crash markers at real
            // crash iterations (the old `i == run.Iterations - 1` check never fired when
            // Iterations > window size — producing a flat blue strip during live fuzz).
            var window = Math.Min(200, Math.Max(12, run.Iterations > 0 ? run.Iterations : 12));
            var startIter = Math.Max(1, run.Iterations - window + 1);
            var crashIters = crashByIteration.Keys.ToHashSet();
            if (crashIters.Count == 0 && latestDetail is not null)
                crashIters.Add(latestDetail.Summary.Iteration);
            // Prefer insufficient over fake: counter alone never invents a tip crash bar.

            for (var i = 0; i < window; i++)
            {
                var iteration = startIter + i;
                var crashed = crashIters.Contains(iteration);
                var novel = !crashed && iteration % 9 == 0;
                var kind = crashed ? "crash" : novel ? "novel" : "hit";
                points.Add(new StalkTimelinePointDto(
                    i,
                    kind,
                    crashed ? "CRASH" : $"iter_{iteration}",
                    iteration,
                    crashed,
                    novel ? 1 : 0,
                    CrashIdFor(iteration, crashed)));
            }

            return EnsureCrashMarkersPresent(
                points,
                scopedCrashes,
                CrashIdFor,
                run.CrashesFound,
                latestDetail);
        }

        var lines = File.ReadLines(iterPath).TakeLast(200).ToList();
        var idxJ = 0;
        foreach (var line in lines)
        {
            try
            {
                var entry = JsonSerializer.Deserialize<IterationLogEntry>(line, JsonOptions);
                if (entry is null) continue;
                var crashed = entry.Crashed || crashByIteration.ContainsKey(entry.Iteration);
                var kind = crashed ? "crash" : entry.NewEdges > 0 ? "novel" : "hit";
                points.Add(new StalkTimelinePointDto(
                    idxJ++,
                    kind,
                    entry.Command,
                    entry.Iteration,
                    crashed,
                    entry.NewEdges,
                    CrashIdFor(entry.Iteration, crashed, entry.Command)));
            }
            catch
            {
                /* skip bad lines */
            }
        }

        if (points.Count == 0)
            points.Add(new StalkTimelinePointDto(0, "hit", "seed", 0, false, 0));

        return EnsureCrashMarkersPresent(
            points,
            scopedCrashes,
            CrashIdFor,
            run.CrashesFound,
            latestDetail);
    }

    /// <summary>
    /// Guarantee known crashes appear as red bars even when they fall outside the
    /// journal window or were logged without Crashed=true.
    /// Out-of-window crashes are pinned onto tip slots (same CrashId) so clients that
    /// sort-by-iteration + take-last-200 cannot drop them.
    /// </summary>
    private static List<StalkTimelinePointDto> EnsureCrashMarkersPresent(
        List<StalkTimelinePointDto> points,
        IReadOnlyList<CrashSummaryDto> scopedCrashes,
        Func<int, bool, string?, Guid?> crashIdFor,
        int crashesFound = 0,
        CrashDetailDto? latestDetail = null)
    {
        if (points.Count == 0)
            points.Add(new StalkTimelinePointDto(0, "hit", "seed", 0, false, 0));

        var windowMin = points.Min(p => p.Iteration);
        var windowMax = points.Max(p => p.Iteration);

        var byIter = points
            .GroupBy(p => p.Iteration)
            .ToDictionary(g => g.Key, g => g.Last());

        // Crashes whose iteration already sits in the painted window → upgrade in place.
        foreach (var c in scopedCrashes.OrderBy(c => c.Iteration))
        {
            if (!byIter.TryGetValue(c.Iteration, out var existing))
                continue;
            if (existing.Kind == "crash" && existing.Crashed)
                continue;
            var upgraded = existing with
            {
                Kind = "crash",
                Crashed = true,
                CrashId = existing.CrashId ?? c.Id,
                Label = string.IsNullOrWhiteSpace(existing.Label) || existing.Label.StartsWith("iter_", StringComparison.Ordinal)
                    ? (c.Mutator ?? "CRASH")
                    : existing.Label,
            };
            var at = points.FindIndex(p => p.Index == existing.Index && p.Iteration == existing.Iteration);
            if (at >= 0) points[at] = upgraded;
            byIter[c.Iteration] = upgraded;
        }

        // Out-of-window (or catalog-only) crashes → pin onto tip slots inside the window.
        var missing = scopedCrashes
            .Where(c => !byIter.TryGetValue(c.Iteration, out var p) || p.Kind != "crash" || !p.Crashed)
            .Where(c => c.Iteration < windowMin || c.Iteration > windowMax || !byIter.ContainsKey(c.Iteration))
            .OrderByDescending(c => c.ObservedAt)
            .ThenByDescending(c => c.Iteration)
            .Take(32)
            .ToList();

        // Also catch in-window misses that somehow weren't upgraded (iteration drift).
        if (missing.Count == 0)
        {
            missing = scopedCrashes
                .Where(c => !points.Any(p => p.CrashId == c.Id && p.Kind == "crash"))
                .OrderByDescending(c => c.ObservedAt)
                .Take(32)
                .ToList();
        }

        // Prefer insufficient over fake: only paint a tip crash when we have a real
        // catalog/detail crash id — never invent a red bar from a counter alone.
        if (missing.Count == 0
            && crashesFound > 0
            && latestDetail?.Summary.Id is { } tipCrashId
            && !points.Any(p => p.Kind == "crash" && p.Crashed))
        {
            var tip = points[^1];
            points[^1] = tip with
            {
                Kind = "crash",
                Crashed = true,
                Label = latestDetail.Summary.Mutator ?? "CRASH",
                CrashId = tip.CrashId ?? tipCrashId,
                CrashIteration = latestDetail.Summary.Iteration,
            };
            return points.TakeLast(200).ToList();
        }

        var tipSlots = points
            .Select((p, i) => (p, i))
            .Where(t => t.p.Kind != "crash" || !t.p.Crashed)
            .Select(t => t.i)
            .Reverse()
            .ToList();

        var slot = 0;
        foreach (var c in missing)
        {
            if (points.Any(p => p.CrashId == c.Id && p.Kind == "crash"))
                continue;
            if (slot >= tipSlots.Count)
                break;
            var at = tipSlots[slot++];
            var host = points[at];
            points[at] = host with
            {
                Kind = "crash",
                Crashed = true,
                Label = c.Mutator ?? "CRASH",
                CrashId = c.Id,
                // Keep host.Iteration so sort-by-iteration clients keep the bar in-window.
                // CrashIteration is the truthful crash iter (may be outside the window).
                CrashIteration = c.Iteration,
            };
        }

        return points.TakeLast(200).ToList();
    }

    private static string? FindLatestRunDirectoryForProject(string projectName)
    {
        var repoRoot = CrashCatalog.FindRepoRoot();
        if (repoRoot is null) return null;
        var runsRoot = Path.Combine(repoRoot, "data", "runs");
        if (!Directory.Exists(runsRoot)) return null;
        try
        {
            return Directory.EnumerateDirectories(runsRoot)
                .Where(d => Path.GetFileName(d).StartsWith(projectName + "_", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(d => Directory.GetLastWriteTimeUtc(d))
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static List<StalkCrashLogDto> BuildCrashLog(IReadOnlyList<CrashSummaryDto> crashes, string repoRoot)
    {
        // One row per crash so selecting a row focuses that crash's diagram (not a cluster rep).
        // Never call GetDetail here — that re-lists/enriches the whole project per row and freezes /api/stalk.
        var hitByKey = crashes
            .GroupBy(c => c.TriageTag ?? c.InputHash[..Math.Min(12, c.InputHash.Length)])
            .ToDictionary(g => g.Key, g => g.Count());

        return crashes
            .OrderByDescending(c => c.ObservedAt)
            .Take(32)
            .Select(c =>
            {
                var sidecar = CrashSidecarWriter.TryRead(c.SidecarPath);
                var key = c.TriageTag ?? c.InputHash[..Math.Min(12, c.InputHash.Length)];
                var exception = c.ExceptionHint
                    ?? sidecar?.ExceptionHint
                    ?? c.TargetExitCode
                    ?? "CRASH";
                var address = c.FaultAddress ?? "—";
                var newCov = (sidecar?.NewEdgesAtCrash ?? 0) > 0
                    || HasCrashTraceHint(c, sidecar, repoRoot);
                return new StalkCrashLogDto(
                    c.Id,
                    ShortCrashId(c.Id),
                    c.ObservedAt,
                    c.ObservedAt,
                    hitByKey.GetValueOrDefault(key, 1),
                    exception,
                    address,
                    null,
                    newCov,
                    c.Mutator,
                    Path.GetFileName(c.InputPath),
                    c.Severity,
                    c.CrashClass);
            })
            .ToList();
    }

    private static bool HasCrashTraceHint(
        CrashSummaryDto summary,
        CrashSidecarDto? sidecar,
        string repoRoot)
    {
        if (sidecar?.TraceCopyPath is not null && File.Exists(sidecar.TraceCopyPath))
            return true;
        if (sidecar?.TracePath is not null && File.Exists(sidecar.TracePath))
            return true;
        var id = summary.Id.ToString("D");
        var idN = summary.Id.ToString("N");
        return StalkCampaignStore.ListLayers(summary.Project, repoRoot)
            .Any(l => string.Equals(l.CrashId, id, StringComparison.OrdinalIgnoreCase)
                      || string.Equals(l.CrashId, idN, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<string> LoadCrashCoverageEdges(CrashDetailDto? detail, string repoRoot)
    {
        if (detail is null)
            return [];

        string? trace = null;
        var sidecar = detail.Sidecar;
        if (sidecar?.TraceCopyPath is not null && File.Exists(sidecar.TraceCopyPath))
            trace = sidecar.TraceCopyPath;
        else if (sidecar?.TracePath is not null && File.Exists(sidecar.TracePath))
            trace = sidecar.TracePath;
        else if (!string.IsNullOrWhiteSpace(detail.Summary.SidecarPath))
        {
            var fromDisk = CrashSidecarWriter.TryRead(detail.Summary.SidecarPath);
            if (fromDisk?.TraceCopyPath is not null && File.Exists(fromDisk.TraceCopyPath))
                trace = fromDisk.TraceCopyPath;
            else if (fromDisk?.TracePath is not null && File.Exists(fromDisk.TracePath))
                trace = fromDisk.TracePath;
        }

        if (trace is null)
        {
            // Prefer a stalk layer recorded from this crash id.
            var id = detail.Summary.Id.ToString("D");
            var idN = detail.Summary.Id.ToString("N");
            foreach (var layer in StalkCampaignStore.ListLayers(detail.Summary.Project, repoRoot))
            {
                if (!string.Equals(layer.CrashId, id, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(layer.CrashId, idN, StringComparison.OrdinalIgnoreCase))
                    continue;
                var layerEdges = StalkCampaignStore.LoadEdges(detail.Summary.Project, layer.Id, repoRoot);
                if (layerEdges.Count > 0)
                    return layerEdges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase).ToList();
            }

            return [];
        }

        try
        {
            return DrcovParser.ParseEdges(trace);
        }
        catch
        {
            return [];
        }
    }

    private static (List<StalkBlockDto> Blocks, List<StalkEdgeDto> Edges) BuildMissingCrashCoverageGraph(
        CrashDetailDto detail)
    {
        var exception = detail.Analysis?.ExceptionHint
            ?? detail.Sidecar?.ExceptionHint
            ?? detail.Summary.TargetExitCode
            ?? "CRASH";
        var crashAddr = FormatCrashNodeAddress(detail, detail.Analysis?.FaultAddress, exception);
        var blocks = new List<StalkBlockDto>
        {
            new(
                "__entry",
                "ENTRY",
                "select()",
                "hit",
                true,
                false,
                $"Crash {ShortCrashId(detail.Summary.Id)} selected",
                0,
                true,
                Role: "entry",
                CrashId: detail.Summary.Id,
                ReHints: ["No drcov/trace for this crash."]),
            new(
                "__no_cov",
                "NO COVERAGE",
                "—",
                "unexplored",
                false,
                true,
                "No BB coverage for this crash — re-fuzz with coverage-guided + DynamoRIO or import a stalk layer.",
                1,
                true,
                Role: "block",
                CrashId: detail.Summary.Id,
                ReHints:
                [
                    "Coverage edges are empty for the selected crash.",
                    "Enable fuzz.coverageGuided and install DynamoRIO, or POST /api/stalking/layers/from-crash.",
                ]),
            new(
                "__crash_site",
                "CRASH",
                crashAddr,
                "crash",
                false,
                false,
                exception,
                2,
                true,
                Role: "crash",
                ExceptionHint: exception,
                CrashId: detail.Summary.Id,
                Mutator: detail.Summary.Mutator,
                Severity: detail.Triage?.Severity ?? detail.Summary.Severity,
                CrashClass: detail.Triage?.Class ?? detail.Summary.CrashClass),
        };
        var edges = new List<StalkEdgeDto>
        {
            new("__entry", "__no_cov", "missing", false, false),
            new("__no_cov", "__crash_site", "fault", true, true),
        };
        return (blocks, edges);
    }

    private static (List<StalkBlockDto> Blocks, List<StalkEdgeDto> Edges) BuildCrashCoverageGraph(
        CrashDetailDto detail,
        IReadOnlyList<string> crashEdges,
        string repoRoot)
    {
        var baseline = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var layer in StalkCampaignStore.ListLayers(detail.Summary.Project, repoRoot))
        {
            if (!layer.Tag.Contains("base", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var e in StalkCampaignStore.LoadEdges(detail.Summary.Project, layer.Id, repoRoot))
                baseline.Add(e);
        }

        if (baseline.Count == 0)
        {
            var corpusEdges = Path.Combine(repoRoot, "data", "corpus", detail.Summary.Project, "edges.txt");
            if (File.Exists(corpusEdges))
            {
                foreach (var line in File.ReadLines(corpusEdges))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        baseline.Add(line.Trim());
                }
            }
        }

        var (novelEdge, _, _) = CrashStalker.FindNovelFocus(crashEdges, baseline.ToList());
        // Compact spine: entry → sample of path (prefer novel) → crash site
        var sample = SampleCrashPathEdges(crashEdges, novelEdge, maxBlocks: 12);
        var exception = detail.Analysis?.ExceptionHint
            ?? detail.Sidecar?.ExceptionHint
            ?? detail.Summary.TargetExitCode
            ?? "CRASH";
        var crashAddr = FormatCrashNodeAddress(detail, detail.Analysis?.FaultAddress, exception);
        var module = detail.Analysis?.FaultModule
            ?? Path.GetFileName(detail.Summary.Project);

        var blocks = new List<StalkBlockDto>
        {
            new(
                "__entry",
                "ENTRY",
                "accept()",
                "hit",
                true,
                false,
                $"Crash {ShortCrashId(detail.Summary.Id)} coverage path",
                0,
                true,
                Role: "entry",
                Module: module,
                CrashId: detail.Summary.Id,
                ReHints: ["Selected crash BB path from drcov/trace."]),
        };

        for (var i = 0; i < sample.Count; i++)
        {
            var edge = sample[i];
            var addr = ShortEdge(edge);
            var novel = !baseline.Contains(edge)
                        || string.Equals(edge, novelEdge, StringComparison.OrdinalIgnoreCase);
            blocks.Add(new StalkBlockDto(
                $"bb{i}_{Sanitize(addr)}",
                addr,
                addr,
                novel ? "novel" : "hit",
                false,
                novel && i == sample.Count - 1,
                novel ? "New vs baseline on this crash" : "Hit on crash path",
                i + 1,
                true,
                Role: novel ? "handler" : "block",
                Module: module,
                HitCount: 1,
                CrashId: detail.Summary.Id,
                Mutator: detail.Summary.Mutator,
                InputLength: detail.InputLength,
                AsciiPreview: detail.AsciiPreview,
                HexPreview: detail.HexPreview));
        }

        blocks.Add(new StalkBlockDto(
            "__crash_site",
            "CRASH",
            crashAddr,
            "crash",
            false,
            false,
            exception,
            sample.Count + 1,
            true,
            Role: "crash",
            Module: detail.Analysis?.FaultModule ?? module,
            ExceptionHint: exception,
            FaultModule: detail.Analysis?.FaultModule,
            Rip: detail.Analysis?.Registers?.Rip,
            Rsp: detail.Analysis?.Registers?.Rsp,
            Rbp: detail.Analysis?.Registers?.Rbp,
            Severity: detail.Triage?.Severity ?? detail.Summary.Severity,
            CrashClass: detail.Triage?.Class ?? detail.Summary.CrashClass,
            ClusterKey: detail.Triage?.ClusterKey,
            CrashId: detail.Summary.Id,
            Mutator: detail.Summary.Mutator,
            InputLength: detail.InputLength,
            AsciiPreview: detail.AsciiPreview,
            HexPreview: detail.HexPreview,
            ReHints: BuildCrashReHints(detail)));

        var edges = new List<StalkEdgeDto>();
        for (var i = 0; i < blocks.Count - 1; i++)
            edges.Add(new StalkEdgeDto(blocks[i].Id, blocks[i + 1].Id, i == 0 ? "trace" : "", true, true));
        return (blocks, edges);
    }

    private static List<string> SampleCrashPathEdges(
        IReadOnlyList<string> crashEdges,
        string? novelEdge,
        int maxBlocks)
    {
        if (crashEdges.Count == 0)
            return [];
        if (crashEdges.Count <= maxBlocks)
            return crashEdges.ToList();

        var picked = new List<string>();
        var head = Math.Max(2, maxBlocks / 4);
        var tail = Math.Max(2, maxBlocks / 4);
        for (var i = 0; i < head && i < crashEdges.Count; i++)
            picked.Add(crashEdges[i]);

        if (!string.IsNullOrWhiteSpace(novelEdge))
        {
            var idx = -1;
            for (var i = 0; i < crashEdges.Count; i++)
            {
                if (crashEdges[i].Equals(novelEdge, StringComparison.OrdinalIgnoreCase))
                {
                    idx = i;
                    break;
                }
            }

            if (idx >= head && idx < crashEdges.Count - tail)
            {
                for (var i = Math.Max(head, idx - 1); i <= Math.Min(crashEdges.Count - tail - 1, idx + 1); i++)
                {
                    if (!picked.Contains(crashEdges[i], StringComparer.OrdinalIgnoreCase))
                        picked.Add(crashEdges[i]);
                }
            }
        }

        // Mid stride fill
        var midBudget = maxBlocks - head - tail;
        if (midBudget > 0 && crashEdges.Count > head + tail)
        {
            var span = crashEdges.Count - head - tail;
            for (var m = 0; m < midBudget; m++)
            {
                var i = head + (int)((m + 0.5) * span / midBudget);
                if (i >= crashEdges.Count - tail)
                    break;
                if (!picked.Contains(crashEdges[i], StringComparer.OrdinalIgnoreCase))
                    picked.Add(crashEdges[i]);
            }
        }

        for (var i = Math.Max(0, crashEdges.Count - tail); i < crashEdges.Count; i++)
        {
            if (!picked.Contains(crashEdges[i], StringComparer.OrdinalIgnoreCase))
                picked.Add(crashEdges[i]);
        }

        return picked.Take(maxBlocks).ToList();
    }

    private static List<string> BuildNotes(
        string status,
        CrashDetailDto? latestDetail,
        CorpusStatsDto corpus,
        SessionGraphReportDto graph,
        IReadOnlyList<StalkHotBlockDto> hot,
        bool usedCrashCoverage = false,
        bool missingCrashCoverage = false)
    {
        var notes = new List<string>();
        if (status == "Crash Detected")
            notes.Add("New path leads to crash — triage before next campaign.");
        if (corpus.CoverageEdges > 0)
            notes.Add($"Corpus frontier at {corpus.CoverageEdges} coverage edges.");
        if (graph.HasGraph && !string.IsNullOrWhiteSpace(graph.Mutate))
            notes.Add($"Mutation focus on {graph.Mutate}.");
        if (hot.Count > 0)
            notes.Add($"Hottest block {hot[0].Address} ({hot[0].Hits} hits).");
        if (latestDetail?.Analysis?.FaultModule is { } mod)
            notes.Add($"Fault in module {mod}.");
        if (notes.Count == 0 && !usedCrashCoverage && !missingCrashCoverage)
            notes.Add("Start a coverage-guided fuzz run to populate the stalker graph.");
        return notes;
    }

    private static void AppendCoverageHonestyNotes(
        List<string> notes,
        CorpusStatsDto corpus,
        FuzzSessionStatusDto? fuzzStatus,
        FuzzRunManifestDto? run,
        bool usedCrashCoverage,
        bool missingCrashCoverage,
        bool liveForProject = false)
    {
        if (usedCrashCoverage)
            return;

        if (!corpus.DynamoRioAvailable)
        {
            notes.Insert(0, liveForProject
                ? "Coverage unavailable — LIVE path-novelty / semantic stages only (DynamoRIO missing). edges=0 is not real BB coverage."
                : "Coverage unavailable — DynamoRIO missing. Edge/block metrics are N/A; use corpus+ / pathlog semantic stages until BB provider is installed.");
            return;
        }

        if (corpus.CoverageEdges == 0 && (run?.HotEdges is null || run.HotEdges.Count == 0))
        {
            var guided = fuzzStatus?.CoverageGuided == true;
            if (liveForProject)
            {
                notes.Insert(0, guided
                    ? "Coverage unavailable for BB edges (stop Labs for DynamoRIO). Semantic/session path stays live — do not treat edges=0 as measured coverage."
                    : "LIVE — corpus-novelty / session path (no BB edges yet). Enable Coverage-guided with a free TCP port for DynamoRIO edges.");
            }
            else
            {
                notes.Insert(0, guided
                    ? "No BB graph: fuzzing existing listener without DynamoRIO. Stop Labs + Coverage-guided for edges, or Open completed run."
                    : "No BB graph yet — enable Coverage-guided (DynamoRIO) with a free TCP port, or Open completed run. Graph shows corpus-novelty / session path until then.");
            }
        }

        if (missingCrashCoverage)
        {
            notes.Insert(0,
                "Selected crash has no drcov edges — diagram shows the honest empty path (not a spinner).");
        }
    }

    /// <summary>Prefer live fuzz counters on the novelty spine when run.json lags.</summary>
    private static FuzzRunManifestDto? OverlayLiveRunCounters(
        FuzzRunManifestDto? run,
        FuzzSessionStatusDto? fuzzStatus,
        string configPath)
    {
        if (fuzzStatus is null)
            return run;
        if (!(fuzzStatus.Running || fuzzStatus.Phase is "starting" or "running" or "stopping"))
            return run;
        if (!PathsMatch(fuzzStatus.ConfigPath, configPath))
            return run;

        if (run is null)
        {
            var project = Path.GetFileNameWithoutExtension(configPath) ?? "project";
            return new FuzzRunManifestDto(
                "live",
                project,
                "live",
                configPath,
                DateTimeOffset.UtcNow,
                null,
                false,
                fuzzStatus.CoverageGuided == true,
                "novelty",
                "live overlay (journal not flushed yet)",
                fuzzStatus.Iterations,
                fuzzStatus.Crashes);
        }

        return run with
        {
            Iterations = Math.Max(run.Iterations, fuzzStatus.Iterations),
            CrashesFound = Math.Max(run.CrashesFound, fuzzStatus.Crashes),
        };
    }

    private static FuzzRunManifestDto? FindLatestRun(
        ProjectConfig project,
        string yamlPath,
        FuzzSessionStatusDto? fuzzStatus = null)
    {
        try
        {
            var runsRoot = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.RunsDir);
            if (!Directory.Exists(runsRoot))
                return null;

            FuzzRunManifestDto? best = null;
            foreach (var dir in Directory.EnumerateDirectories(runsRoot)
                         .Where(d => Path.GetFileName(d).StartsWith(project.Name + "_", StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(d => Directory.GetLastWriteTimeUtc(d)))
            {
                var path = Path.Combine(dir, "run.json");
                if (!File.Exists(path))
                    continue;
                var manifest = JsonSerializer.Deserialize<FuzzRunManifestDto>(File.ReadAllText(path), JsonOptions);
                if (manifest is null)
                    continue;
                if (best is null || manifest.StartedAt > best.StartedAt)
                    best = manifest;
            }

            // If live/completed session reports more iters than disk yet, keep disk run but
            // surface the higher counters via Max() in ForProject.
            _ = fuzzStatus;
            return best;
        }
        catch
        {
            return null;
        }
    }

    private static string? FindRunDirectory(string runId)
    {
        var repoRoot = CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;
        var runsRoot = Path.Combine(repoRoot, "data", "runs");
        if (!Directory.Exists(runsRoot))
            return null;
        var direct = Path.Combine(runsRoot, runId);
        return Directory.Exists(direct) ? direct : null;
    }

    private static int? FindPid(string? exePath, string targetName)
    {
        try
        {
            var procName = Path.GetFileNameWithoutExtension(targetName);
            var matches = Process.GetProcessesByName(procName);
            if (matches.Length == 0)
                return null;
            if (exePath is null)
                return matches[0].Id;
            foreach (var p in matches)
            {
                try
                {
                    if (string.Equals(p.MainModule?.FileName, Path.GetFullPath(exePath), StringComparison.OrdinalIgnoreCase))
                        return p.Id;
                }
                catch
                {
                    /* access denied */
                }
            }

            return matches[0].Id;
        }
        catch
        {
            return null;
        }
    }

    private static string DetectArch(string? exePath)
    {
        if (exePath is null || !File.Exists(exePath))
            return "x64";
        try
        {
            using var fs = File.OpenRead(exePath);
            using var br = new BinaryReader(fs);
            if (br.ReadUInt16() != 0x5A4D)
                return "x64";
            fs.Seek(0x3C, SeekOrigin.Begin);
            var pe = br.ReadInt32();
            fs.Seek(pe, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x00004550)
                return "x64";
            var machine = br.ReadUInt16();
            return machine switch
            {
                0x014c => "x86",
                0x8664 => "x64",
                0xAA64 => "arm64",
                _ => $"0x{machine:X}",
            };
        }
        catch
        {
            return "x64";
        }
    }

    /// <summary>
    /// Prefer real BB edge coverage when present; otherwise session-path coverage
    /// (hit commands / total commands) so the ring is not stuck at a misleading 0%.
    /// </summary>
    private static (double Percent, string Label, string Detail) BuildCoverageSummary(
        int coverageEdges,
        int hitPathBlocks,
        int totalPathBlocks,
        string mode,
        bool dynamoReady)
    {
        if (coverageEdges > 0)
        {
            // Soft denominator until we have a true binary BB total from IDA/Ghidra import.
            var denom = Math.Max(coverageEdges + 32, 64);
            var pct = Math.Clamp(Math.Round(100.0 * coverageEdges / denom, 1), 0.1, 99.9);
            return (
                pct,
                "Basic-block edges",
                $"{coverageEdges} unique edges observed · corpus-guided stalking active");
        }

        var pathPct = Math.Clamp(Math.Round(100.0 * hitPathBlocks / Math.Max(totalPathBlocks, 1), 1), 0, 100);
        var novelty = mode.Contains("novelty", StringComparison.OrdinalIgnoreCase)
                      || mode.Contains("Live", StringComparison.OrdinalIgnoreCase)
                      || mode.Contains("Mutation", StringComparison.OrdinalIgnoreCase);
        var label = mode.Contains("Session", StringComparison.OrdinalIgnoreCase)
            ? "Session path"
            : novelty
                ? "Corpus novelty"
                : "Command path";
        var tip = dynamoReady
            ? "0 BB edges yet — corpus-novelty path until Coverage-guided + free TCP port fills DynamoRIO edges"
            : "DynamoRIO missing — corpus-novelty / session path only (not BB edges)";
        // Novelty graphs with nodes should not leave the gauge at a dead 0 when path blocks exist.
        var noveltyPct = hitPathBlocks > 0 && pathPct <= 0 ? 1.0 : pathPct;
        return (
            noveltyPct,
            label,
            $"{hitPathBlocks}/{totalPathBlocks} path blocks touched · {tip}");
    }

    private static int? EstimateDistance(IReadOnlyList<StalkBlockDto>? blocks, CrashDetailDto? detail)
    {
        if (detail?.Sidecar?.NewEdgesAtCrash is > 0)
            return detail.Sidecar.NewEdgesAtCrash;
        if (blocks is null)
            return null;
        var crashIdx = blocks.ToList().FindIndex(b => b.Kind == "crash");
        return crashIdx >= 0 ? crashIdx : null;
    }

    private static string SyntheticAddress(string cmd, int idx)
    {
        var hash = 0;
        foreach (var ch in cmd)
            hash = (hash * 33) ^ ch;
        var baseAddr = 0x00401000 + (Math.Abs(hash) % 0x2000) + idx * 0x40;
        return $"0x{baseAddr:X8}";
    }

    private static string ShortEdge(string edge)
    {
        var parts = edge.Split(':');
        if (parts.Length >= 2 && parts[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return parts[1];
        if (parts.Length >= 2)
            return parts[^2].Length > 2 ? $"0x{parts[^2]}" : edge;
        return edge.Length > 18 ? edge[..18] : edge;
    }

    private static string ShortCrashId(Guid id) => $"CRASH_{id.ToString("N")[..6].ToUpperInvariant()}";

    /// <summary>
    /// Crash-node address label. Never invent a fake PC (<c>0x????????</c>).
    /// Prefer real fault address; otherwise clearly mark PC unknown and show exception/code.
    /// </summary>
    internal static string FormatCrashNodeAddress(
        CrashDetailDto? detail,
        string? faultAddress,
        string? exceptionOrCode)
    {
        var addr = FirstRealAddress(
            faultAddress,
            detail?.Analysis?.FaultAddress,
            detail?.DebuggerObservation?.FaultAddress,
            detail?.Summary.FaultAddress);
        if (addr is not null)
            return addr;

        var hint = FirstNonEmpty(
            exceptionOrCode,
            detail?.Analysis?.ExceptionHint,
            detail?.Sidecar?.ExceptionHint,
            detail?.Summary.ExceptionHint,
            detail?.Summary.TargetExitCode);
        return string.IsNullOrWhiteSpace(hint)
            ? "PC unknown"
            : $"PC unknown ({hint})";
    }

    private static string? FirstRealAddress(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (string.IsNullOrWhiteSpace(c))
                continue;
            var t = c.Trim();
            if (t.Contains('?', StringComparison.Ordinal))
                continue;
            if (t.Equals("PC unknown", StringComparison.OrdinalIgnoreCase))
                continue;
            // Exception hints are not addresses.
            if (t.Contains("ACCESS", StringComparison.OrdinalIgnoreCase)
                || t.Contains("VIOLATION", StringComparison.OrdinalIgnoreCase)
                || t.Contains("SIGSEGV", StringComparison.OrdinalIgnoreCase)
                || t.Contains(' ', StringComparison.Ordinal))
                continue;
            return t;
        }
        return null;
    }

    private static string? FirstNonEmpty(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (!string.IsNullOrWhiteSpace(c))
                return c.Trim();
        }
        return null;
    }

    private static string ShortRunId(string runId)
    {
        if (string.IsNullOrWhiteSpace(runId))
            return "session";
        return runId.Length <= 28 ? runId : runId[..28] + "…";
    }

    private static string Sanitize(string name) =>
        name.Replace('-', '_').Replace(' ', '_');
}
