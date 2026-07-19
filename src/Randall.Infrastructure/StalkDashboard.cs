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
        Guid? focusCrashId = null)
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

        var crashes = CrashCatalog.ListAll(repoRoot, project.Name);
        var focusCrash = focusCrashId is Guid fid
            ? crashes.FirstOrDefault(c => c.Id == fid)
            : null;
        var latestCrash = focusCrash ?? crashes.FirstOrDefault();
        CrashDetailDto? latestDetail = latestCrash is null ? null : CrashCatalog.GetDetail(latestCrash.Id, repoRoot);

        var run = FindLatestRun(project, configPath);
        var timeline = BuildTimeline(run, latestDetail, crashes);
        var (blocks, edges) = BuildGraph(project, graph, latestDetail, run);
        var hotBlocks = (run?.HotEdges ?? [])
            .Take(8)
            .Select(h => new StalkHotBlockDto(ShortEdge(h.Edge), h.HitCount))
            .ToList();

        var crashLog = BuildCrashLog(crashes, repoRoot);
        var status = focusCrash is not null
            ? $"Inspecting {ShortCrashId(focusCrash.Id)}"
            : ResolveStatus(fuzzStatus, configPath, latestCrash, pid);
        var mode = project.Fuzz.CoverageGuided || fuzzStatus?.CoverageGuided == true
            ? "Basic Block"
            : graph.HasGraph ? "Session Graph" : "Mutation";

        var notes = BuildNotes(status, latestDetail, corpus, graph, hotBlocks);
        if (focusCrash is not null)
        {
            notes.Insert(0,
                $"Inspecting historical crash {ShortCrashId(focusCrash.Id)} (iteration {focusCrash.Iteration}) — Follow live to resume.");
        }
        var crashAddr = latestDetail?.Analysis?.FaultAddress
            ?? latestDetail?.Sidecar?.ExceptionHint
            ?? "—";
        var exception = latestDetail?.Analysis?.ExceptionHint
            ?? latestDetail?.Sidecar?.ExceptionHint
            ?? latestCrash?.TargetExitCode
            ?? "—";

        var pathBlocks = blocks.Where(b => b.Id is not "__entry" and not "__crash_site").ToList();
        var hitPath = pathBlocks.Count(b => b.Kind is "hit" or "novel" or "crash" || b.OnCrashPath);
        var totalPath = Math.Max(pathBlocks.Count, 1);
        var (coveragePct, coverageLabel, coverageDetail) = BuildCoverageSummary(
            corpus.CoverageEdges,
            hitPath,
            totalPath,
            mode,
            corpus.DynamoRioAvailable);

        var currentBlocks = corpus.CoverageEdges > 0
            ? corpus.CoverageEdges
            : hitPath;
        var baselineBlocks = Math.Max(0, currentBlocks - Math.Max(0, (int)(run?.HotEdges?.Sum(h => h.HitCount > 0 ? 1 : 0) ?? 0)));
        if (baselineBlocks >= currentBlocks && currentBlocks > 0)
            baselineBlocks = Math.Max(0, currentBlocks - Math.Min(12, currentBlocks / 4 + 1));
        var diff = currentBlocks - baselineBlocks;

        var firstDiv = blocks.FirstOrDefault(b => b.OnCrashPath && b.Kind is "novel" or "crash")?.Label
            ?? blocks.FirstOrDefault(b => b.Kind is "novel" or "crash")?.Label
            ?? graph.Mutate
            ?? "—";

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
            fuzzStatus?.Iterations ?? run?.Iterations ?? 0,
            Math.Max(fuzzStatus?.Crashes ?? 0, crashes.Count),
            Math.Max(fuzzStatus?.CoverageEdges ?? 0, corpus.CoverageEdges),
            Math.Max(fuzzStatus?.CorpusAdded ?? 0, corpus.SeenInputs),
            coveragePct,
            coverageLabel,
            coverageDetail,
            run?.RunId,
            run?.StartedAt,
            latestCrash is null ? null : Path.GetFileName(latestCrash.InputPath),
            latestCrash?.ObservedAt.ToString("HH:mm:ss.fff"),
            exception,
            crashAddr,
            latestDetail?.Analysis?.Registers?.Rsp is null ? null : "main",
            latestCrash is null ? null : ShortCrashId(latestCrash.Id),
            crashLog.FirstOrDefault()?.Hits ?? (latestCrash is null ? 0 : 1),
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
        int? pid)
    {
        if (fuzzStatus?.Running == true && PathsMatch(fuzzStatus.ConfigPath, configPath))
        {
            if (fuzzStatus.LastMessage?.Contains("CRASH", StringComparison.OrdinalIgnoreCase) == true)
                return "Crash Detected";
            return "Tracing";
        }

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
        FuzzRunManifestDto? run)
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
            return BuildFallbackGraph(run, latestDetail, crashAddr, exception);

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
            var fault = string.IsNullOrWhiteSpace(crashAddr) ? "0x????????" : crashAddr;
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
            edges.Add(new StalkEdgeDto(Sanitize(path[^1]), "__crash_site", "💥 fault", true, true));

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
        string exception)
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
            blocks.Add(new StalkBlockDto("entry", "entry", "0x00401000", "hit", true, false, "Process entry / accept", 0, true));
            blocks.Add(new StalkBlockDto("parse", "parse", "0x00401120", "hit", false, false, "Parse client input", 1, true));
            blocks.Add(new StalkBlockDto("mutate", "handler", "0x00401240", "novel", false, true, "Vulnerable handler", 2, true));
        }

        if (latestDetail is not null)
        {
            var fault = string.IsNullOrWhiteSpace(crashAddr) ? "0x????????" : crashAddr;
            blocks.Add(new StalkBlockDto(
                "__crash_site",
                "CRASH",
                fault,
                "crash",
                false,
                false,
                $"{exception} at {fault}",
                blocks.Count,
                true));
        }

        var edges = new List<StalkEdgeDto>();
        for (var e = 0; e < blocks.Count - 1; e++)
            edges.Add(new StalkEdgeDto(blocks[e].Id, blocks[e + 1].Id, "", true, true));
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

    private static List<StalkTimelinePointDto> BuildTimeline(
        FuzzRunManifestDto? run,
        CrashDetailDto? latestDetail,
        IReadOnlyList<CrashSummaryDto> crashes)
    {
        var runId = run?.RunId;
        // Prefer crashes from the active run, then newest observation for that iteration.
        var crashByIteration = crashes
            .GroupBy(c => c.Iteration)
            .ToDictionary(
                g => g.Key,
                g => g
                    .OrderByDescending(c =>
                        !string.IsNullOrWhiteSpace(runId)
                        && string.Equals(c.RunId, runId, StringComparison.OrdinalIgnoreCase))
                    .ThenByDescending(c => c.ObservedAt)
                    .First().Id);

        Guid? CrashIdFor(int iteration, bool crashed, string? command = null)
        {
            if (!crashed) return null;
            if (crashByIteration.TryGetValue(iteration, out var id))
                return id;

            // Fallback: nearest crash in the same run (iteration numbers can drift).
            var pool = crashes.Where(c =>
                string.IsNullOrWhiteSpace(runId)
                || string.Equals(c.RunId, runId, StringComparison.OrdinalIgnoreCase));
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
            if (latestDetail is not null)
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
            return points;
        }

        var runDir = FindRunDirectory(run.RunId);
        var iterPath = runDir is null ? null : Path.Combine(runDir, "iterations.jsonl");
        if (iterPath is null || !File.Exists(iterPath))
        {
            for (var i = 0; i < Math.Min(80, Math.Max(10, run.Iterations)); i++)
            {
                var kind = i == run.Iterations - 1 && run.CrashesFound > 0 ? "crash" : i % 9 == 0 ? "novel" : "hit";
                var crashed = kind == "crash";
                var iteration = crashed ? (latestDetail?.Summary.Iteration ?? i) : i;
                points.Add(new StalkTimelinePointDto(
                    i,
                    kind,
                    $"iter_{i}",
                    iteration,
                    crashed,
                    kind == "novel" ? 1 : 0,
                    CrashIdFor(iteration, crashed)));
            }
            return points;
        }

        var lines = File.ReadLines(iterPath).TakeLast(200).ToList();
        var idx = 0;
        foreach (var line in lines)
        {
            try
            {
                var entry = JsonSerializer.Deserialize<IterationLogEntry>(line, JsonOptions);
                if (entry is null) continue;
                var kind = entry.Crashed ? "crash" : entry.NewEdges > 0 ? "novel" : "hit";
                points.Add(new StalkTimelinePointDto(
                    idx++,
                    kind,
                    entry.Command,
                    entry.Iteration,
                    entry.Crashed,
                    entry.NewEdges,
                    CrashIdFor(entry.Iteration, entry.Crashed, entry.Command)));
            }
            catch
            {
                /* skip bad lines */
            }
        }

        if (points.Count == 0)
            points.Add(new StalkTimelinePointDto(0, "hit", "seed", 0, false, 0));

        return points;
    }

    private static List<StalkCrashLogDto> BuildCrashLog(IReadOnlyList<CrashSummaryDto> crashes, string repoRoot)
    {
        var groups = crashes
            .GroupBy(c => c.TriageTag ?? c.InputHash[..Math.Min(12, c.InputHash.Length)])
            .Take(8)
            .Select(g =>
            {
                var first = g.OrderBy(x => x.ObservedAt).First();
                var last = g.OrderByDescending(x => x.ObservedAt).First();
                var detail = CrashCatalog.GetDetail(last.Id, repoRoot);
                var exception = last.ExceptionHint
                    ?? detail?.Analysis?.ExceptionHint
                    ?? detail?.Sidecar?.ExceptionHint
                    ?? last.TargetExitCode
                    ?? "CRASH";
                var address = last.FaultAddress
                    ?? detail?.Analysis?.FaultAddress
                    ?? "—";
                var newCov = (detail?.Sidecar?.NewEdgesAtCrash ?? 0) > 0;
                return new StalkCrashLogDto(
                    last.Id,
                    ShortCrashId(last.Id),
                    first.ObservedAt,
                    last.ObservedAt,
                    g.Count(),
                    exception,
                    address,
                    EstimateDistance(null, detail),
                    newCov,
                    last.Mutator,
                    Path.GetFileName(last.InputPath),
                    last.Severity ?? detail?.Triage?.Severity,
                    last.CrashClass ?? detail?.Triage?.Class);
            })
            .ToList();
        return groups;
    }

    private static List<string> BuildNotes(
        string status,
        CrashDetailDto? latestDetail,
        CorpusStatsDto corpus,
        SessionGraphReportDto graph,
        IReadOnlyList<StalkHotBlockDto> hot)
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
        if (notes.Count == 0)
            notes.Add("Start a coverage-guided fuzz run to populate the stalker graph.");
        return notes;
    }

    private static FuzzRunManifestDto? FindLatestRun(ProjectConfig project, string yamlPath)
    {
        try
        {
            var runsRoot = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.RunsDir);
            if (!Directory.Exists(runsRoot))
                return null;

            FuzzRunManifestDto? best = null;
            foreach (var dir in Directory.EnumerateDirectories(runsRoot)
                         .Where(d => Path.GetFileName(d).StartsWith(project.Name + "_", StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(d => d))
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
        var label = mode.Contains("Session", StringComparison.OrdinalIgnoreCase)
            ? "Session path"
            : "Command path";
        var tip = dynamoReady
            ? "0 BB edges yet — enable Coverage-guided fuzz to fill DynamoRIO edges"
            : "DynamoRIO missing — showing session/command path only";
        return (
            pathPct,
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

    private static string Sanitize(string name) =>
        name.Replace('-', '_').Replace(' ', '_');
}
