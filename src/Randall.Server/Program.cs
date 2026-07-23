using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.ExploitSurface;
using Randall.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();
builder.Services.AddSingleton<FuzzLiveLogBuffer>();
builder.Services.AddSingleton<FuzzSessionManager>();
builder.Services.AddSingleton<SignalRFuzzProgressSink>();
builder.Services.AddSingleton<ProxyManager>();
builder.Services.AddSingleton<CampaignSessionManager>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        // Dashboard JS/CSS change often during local stalker work — avoid stale click handlers.
        var path = ctx.Context.Request.Path.Value ?? "";
        if (path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".html", StringComparison.OrdinalIgnoreCase)
            || path is "/" or "/index.html")
        {
            ctx.Context.Response.Headers.CacheControl = "no-cache, must-revalidate";
        }
    },
});

// Optional lab LAN shared secret (RANDALL_AGENT_TOKEN). Health + static UI stay open.
app.Use(async (ctx, next) =>
{
    var p = ctx.Request.Path.Value ?? "";
    var open = p.Equals("/api/health", StringComparison.OrdinalIgnoreCase)
               || !p.StartsWith("/api/", StringComparison.OrdinalIgnoreCase)
                  && !p.StartsWith("/hubs/", StringComparison.OrdinalIgnoreCase);
    if (!open && !LabAccessHttp.IsAuthorized(ctx.Request))
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new
        {
            error = "Unauthorized — set Authorization: Bearer <token> or X-Randall-Token",
            hint = "Export RANDALL_AGENT_TOKEN on the agent, or pass --token to randall agent/serve",
        });
        return;
    }
    await next();
});

app.MapGet("/randall.png", () => ServeRepoAsset("docs/assets/randall.png", "randall.png"));
app.MapGet("/stalker.png", () => ServeRepoAsset("docs/assets/randal_stalking_bugs.png"));
app.MapGet("/canisters/canister-empty.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-empty.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-empty.jpg"));
app.MapGet("/canisters/canister-low.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-low.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-low.jpg"));
app.MapGet("/canisters/canister-mid.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-mid.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-mid.jpg"));
app.MapGet("/canisters/canister-full.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-full.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-full.jpg"));
app.MapGet("/canisters/canister-eip.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-eip.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-eip.jpg"));
app.MapGet("/canisters/canister-rack.jpg", () => ServeRepoAsset("docs/assets/canisters/canister-rack.jpg", "src/Randall.Server/wwwroot/img/canisters/canister-rack.jpg"));
app.MapGet("/img/canisters/{file}", (string file) =>
{
    var safe = Path.GetFileName(file);
    if (string.IsNullOrWhiteSpace(safe) || safe.Contains("..", StringComparison.Ordinal))
        return Results.NotFound();
    return ServeRepoAsset(
        Path.Combine("docs/assets/canisters", safe),
        Path.Combine("src/Randall.Server/wwwroot/img/canisters", safe));
});

app.MapGet("/api/health", () => new HealthDto("Randfuzz by Randall", "0.16.0-alpha", "phase16-analyze", LabAccess.IsConfigured));

app.MapGet("/api/ui/prefs", () => Results.Ok(UiPrefsStore.Get()));
app.MapPut("/api/ui/prefs", (UiPrefsUpdateRequest request) =>
{
    // Merge onto current prefs so a partial PUT leaves other fields intact.
    var current = UiPrefsStore.Get();

    var theme = request.Theme ?? current.Theme;
    if (!UiPrefsStore.IsValidTheme(theme))
        return Results.BadRequest(new { error = "theme must be dark, light, or cyber" });

    var platform = request.Platform ?? current.Platform;
    if (!UiPrefsStore.IsValidPlatform(platform))
        return Results.BadRequest(new { error = "platform must be auto, windows, or linux" });

    var screamCanisters = request.ScreamCanisters ?? current.ScreamCanisters;
    var screamAnimations = request.ScreamAnimations ?? current.ScreamAnimations;

    var saved = UiPrefsStore.Save(new UiPrefsDto(theme, platform, null, screamCanisters, screamAnimations));
    return Results.Ok(saved);
});

// Host OS + currently resolved fuzzing platform, so the UI can default the selector and
// show only OS-relevant options. "auto" resolves to the real host.
app.MapGet("/api/platform", () =>
{
    var prefs = UiPrefsStore.Get();
    return Results.Ok(new PlatformInfoDto(
        PlatformResolver.Host,
        PlatformResolver.Resolve(prefs.Platform),
        PlatformScope.Selectable));
});

// ELF exploit-mitigation report for a project's target executable (Linux checksec) + ASLR state.
app.MapGet("/api/checksec", (string configPath) =>
{
    if (string.IsNullOrWhiteSpace(configPath))
        return Results.BadRequest(new { error = "configPath required" });
    try
    {
        var yamlPath = Path.GetFullPath(configPath);
        var project = ProjectLoader.Load(yamlPath);
        if (string.IsNullOrWhiteSpace(project.Target.Executable))
            return Results.Ok(new { hasExecutable = false });
        var exe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var resolved = ExecutableResolver.FindExisting(exe);
        if (resolved is null)
            return Results.Ok(new { hasExecutable = false, missing = exe });
        var m = MitigationInspector.Inspect(resolved);
        var aslr = AslrControl.Read();
        return Results.Ok(new
        {
            hasExecutable = true,
            path = resolved,
            m.Nx, m.Canary, m.Pie, m.Relro, m.Fortify, m.Tier,
            aslr = aslr.Label,
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/doctor", (string configPath, string? platform) =>
{
    if (string.IsNullOrWhiteSpace(configPath))
        return Results.BadRequest(new { error = "configPath required" });
    try
    {
        // Fall back to the stored platform preference when the caller doesn't specify one.
        var scope = platform ?? UiPrefsStore.Get().Platform;
        return Results.Ok(LabDoctor.Examine(Path.GetFullPath(configPath), platform: scope));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/graph", (string configPath) =>
{
    if (string.IsNullOrWhiteSpace(configPath))
        return Results.BadRequest(new { error = "configPath required" });
    try
    {
        var yamlPath = Path.GetFullPath(configPath);
        var project = ProjectLoader.Load(yamlPath);
        return Results.Ok(SessionGraphValidator.Validate(project, yamlPath));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/graph", (SessionGraphSaveRequest request) =>
{
    try
    {
        return Results.Ok(CaseRecipeStore.SaveSessionGraph(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/plugins", () => PluginCatalog.ListAll());
app.MapGet("/api/protocols", () => ProtocolCatalog.ListAll());
app.MapGet("/api/campaigns", () => PluginCatalog.ListCampaigns());
app.MapGet("/api/legs", () => RandallLegs.All.Select(l => new LegInfoDto(l.Id, l.Title, l.Summary)));
app.MapGet("/api/roadmap", () => RandallRoadmap.Phases);
app.MapGet("/api/targets", () => CrashCatalog.ListTargets().Where(WebTargetFilter.IsVisible));

// —— Target Runtime (arbitrary exe start/stop/restart; labs are presets on top) ——
app.MapGet("/api/runtime", async (HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(agent))
            return Results.Ok(TargetRuntimeService.List());
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        return Results.Ok(await TargetRuntimeClient.ListAsync(agent, token, ct));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/runtime/{id}", async (string id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.Status(id)
            : await TargetRuntimeClient.StatusAsync(agent, id, token, ct);
        return Results.Ok(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/runtime/start", async (TargetRuntimeStartRequest request, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.Start(request)
            : await TargetRuntimeClient.StartAsync(agent, request, token, ct);
        return st.Ok ? Results.Ok(st) : Results.BadRequest(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/runtime/start-project", async (string yamlPath, string? id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(yamlPath))
            return Results.BadRequest(new { error = "yamlPath required" });
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.StartFromProject(yamlPath, id)
            : await TargetRuntimeClient.StartFromProjectAsync(agent, yamlPath, id, token, ct);
        return st.Ok ? Results.Ok(st) : Results.BadRequest(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/runtime/{id}/stop", async (string id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.Stop(id)
            : await TargetRuntimeClient.StopAsync(agent, id, token, ct);
        return st.Ok ? Results.Ok(st) : Results.BadRequest(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/runtime/{id}/restart", async (string id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.Restart(id)
            : await TargetRuntimeClient.RestartAsync(agent, id, token, ct);
        return st.Ok ? Results.Ok(st) : Results.BadRequest(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/runtime/stop-all", async (HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var st = string.IsNullOrWhiteSpace(agent)
            ? TargetRuntimeService.StopAll()
            : await TargetRuntimeClient.StopAllAsync(agent, token, ct);
        return Results.Ok(st);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/labs", async (HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(agent))
            return Results.Ok(LabServerManager.List());
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        return Results.Ok(await LabAgentClient.ListAsync(agent, token, ct));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/labs/ping", async (HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        if (string.IsNullOrWhiteSpace(agent))
        {
            return Results.Ok(new LabAgentPingDto(true, "local", "Randfuzz by Randall", "local",
                Environment.MachineName, LabAccess.IsConfigured));
        }

        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        return Results.Ok(await LabAgentClient.PingAsync(agent, token, ct));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/labs/{id}/start", async (string id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var r = string.IsNullOrWhiteSpace(agent)
            ? LabServerManager.Start(id)
            : await LabAgentClient.StartAsync(agent, id, token, ct);
        return r.Ok ? Results.Ok(r) : Results.BadRequest(r);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/labs/{id}/stop", async (string id, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var r = string.IsNullOrWhiteSpace(agent)
            ? LabServerManager.Stop(id)
            : await LabAgentClient.StopAsync(agent, id, token, ct);
        return r.Ok ? Results.Ok(r) : Results.BadRequest(r);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/labs/stop-all", async (HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    try
    {
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        var r = string.IsNullOrWhiteSpace(agent)
            ? LabServerManager.StopAll()
            : await LabAgentClient.StopAllAsync(agent, token, ct);
        return Results.Ok(r);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapGet("/api/crashes", (string? project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.Ok(Array.Empty<CrashSummaryDto>());
    return Results.Ok(CrashCatalog.ListAll(projectFilter: project).Where(c => WebTargetFilter.IsVisibleProject(c.Project)));
});
app.MapGet("/api/crashes/clusters", (string? project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.Ok(Array.Empty<CrashClusterDto>());
    return Results.Ok(CrashCatalog.ListClusters(projectFilter: project).Where(c => WebTargetFilter.IsVisibleProject(c.Project)));
});
app.MapGet("/api/crashes/{id:guid}", (Guid id) =>
{
    var detail = CrashCatalog.GetDetail(id);
    if (detail is null)
        return Results.NotFound();
    if (!WebTargetFilter.IsVisibleProject(detail.Summary.Project))
        return Results.NotFound();
    return Results.Ok(detail);
});
app.MapGet("/api/crashes/{id:guid}/memory", (Guid id) =>
{
    var detail = CrashCatalog.GetDetail(id);
    if (detail is null)
        return Results.NotFound();
    if (!WebTargetFilter.IsVisibleProject(detail.Summary.Project))
        return Results.NotFound();

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var crashesDir = Path.Combine(repo, "data", "crashes", detail.Summary.Project);
    var existing = MemoryLensWriter.TryRead(crashesDir, id);
    if (existing is not null)
        return Results.Ok(existing);

    var dump = detail.Summary.MiniDumpPath ?? detail.Analysis?.DumpPath;
    var report = MemoryLensAnalyzer.AnalyzeDump(dump, detail.Analysis);
    if (report.Ok || !string.IsNullOrWhiteSpace(dump))
        MemoryLensWriter.Write(crashesDir, id, report);
    return report.Ok ? Results.Ok(report) : Results.Ok(report);
});
app.MapGet("/api/crashes/{id:guid}/timeline", (Guid id) =>
{
    var detail = CrashCatalog.GetDetail(id);
    if (detail is null)
        return Results.NotFound();
    if (!WebTargetFilter.IsVisibleProject(detail.Summary.Project))
        return Results.NotFound();

    if (detail.MiniTimeline is not null)
        return Results.Ok(detail.MiniTimeline);

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var crashesDir = Path.Combine(repo, "data", "crashes", detail.Summary.Project);
    var existing = MiniTimelineCapture.TryRead(crashesDir, id);
    return existing is not null ? Results.Ok(existing) : Results.NotFound(new
    {
        error = "No mini-timeline for this crash. Enable fuzz.miniTimeline or run: randall timeline capture -p <project> -i <guid>",
    });
});

app.MapGet("/api/crashes/{id:guid}/timeline/graph", (Guid id) =>
{
    var detail = CrashCatalog.GetDetail(id);
    if (detail is null)
        return Results.NotFound();
    if (!WebTargetFilter.IsVisibleProject(detail.Summary.Project))
        return Results.NotFound();

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var crashesDir = Path.Combine(repo, "data", "crashes", detail.Summary.Project);
    var graph = MiniTimelineGraphBuilder.TryRead(crashesDir, id);
    if (graph is not null)
        return Results.Ok(graph);

    var summary = detail.MiniTimeline ?? MiniTimelineCapture.TryRead(crashesDir, id);
    if (summary is null)
    {
        return Results.NotFound(new
        {
            error = "No mini-timeline/graph for this crash. Run: randall timeline capture -p <project> -i <guid>",
        });
    }

    MiniTimelineGraphBuilder.Write(crashesDir, id, summary, detail.Summary.InputPath);
    graph = MiniTimelineGraphBuilder.TryRead(crashesDir, id);
    return graph is not null
        ? Results.Ok(graph)
        : Results.NotFound(new { error = "Graph rebuild failed" });
});

// Crash artifact pack — offline backup of dumps + lens; pull from remote agent into laptop console.
app.MapPost("/api/crashes/pack", (CrashArtifactPackRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Project))
        return Results.BadRequest(new { error = "project required" });
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        var result = CrashArtifactPack.Export(request.Project, request.OutputPath, request.IncludeRuns);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/crashes/pack/download", (string project, bool? includeRuns) =>
{
    if (string.IsNullOrWhiteSpace(project))
        return Results.BadRequest(new { error = "project required" });
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        var result = CrashArtifactPack.Export(project, outputPath: null, includeRuns: includeRuns ?? true);
        var stream = File.OpenRead(result.Path);
        var fileName = Path.GetFileName(result.Path);
        return Results.File(stream, "application/zip", fileName);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/crashes/pack/import", (CrashArtifactPackImportRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.ZipPath))
        return Results.BadRequest(new { error = "zipPath required" });
    try
    {
        var result = CrashArtifactPack.Import(Path.GetFullPath(request.ZipPath), overwriteFiles: request.OverwriteFiles);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/crashes/pack/pull", async (CrashArtifactPackPullRequest request, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.AgentUrl) || string.IsNullOrWhiteSpace(request.Project))
        return Results.BadRequest(new { error = "agentUrl and project required" });
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        var result = await CrashArtifactPack.PullFromAgentAsync(
            request.AgentUrl, request.Project, request.OutputPath, request.IncludeRuns,
            token: request.AgentToken, ct: ct);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/runtime/inspect", async (int? pid, HttpRequest http, string? agent, string? agentToken, CancellationToken ct) =>
{
    if (pid is null or <= 0)
        return Results.BadRequest(new { error = "pid query required" });
    try
    {
        if (string.IsNullOrWhiteSpace(agent))
            return Results.Ok(MemoryLensAnalyzer.AnalyzeLivePid(pid.Value));
        var token = LabAccessHttp.ResolveOutboundAgentToken(http, agentToken);
        return Results.Ok(await TargetRuntimeClient.InspectAsync(agent, pid.Value, token, ct));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/coverage/status", () =>
{
    var dr = DynamoRioRunner.Discover();
    return new
    {
        dynamoRioAvailable = dr.IsAvailable,
        drrunPath = dr.DrrunPath,
    };
});

app.MapGet("/api/corpus/{project}", (string project) => CorpusStats.ForProject(project));

app.MapGet("/api/stalk/{project}", (string project, string? crashId, FuzzSessionManager sessions) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    Guid? focusId = null;
    if (!string.IsNullOrWhiteSpace(crashId))
    {
        if (!Guid.TryParse(crashId, out var parsed))
            return Results.BadRequest(new { error = "crashId must be a guid" });
        focusId = parsed;
    }
    var dash = StalkDashboard.ForProject(project, sessions.Status, focusId);
    return dash is null ? Results.NotFound(new { error = "project not found" }) : Results.Ok(dash);
});

app.MapGet("/api/stalking/{project}", (string project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    return Results.Ok(StalkCampaignStore.Workspace(project));
});

app.MapGet("/api/stalking/{project}/layers", (string project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    return Results.Ok(StalkCampaignStore.ListLayers(project));
});

app.MapPost("/api/stalking/layers", (StalkLayerCreateRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(StalkCampaignStore.AddLayer(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/stalking/layers/from-crash", (StalkLayerFromCrashRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.CrashId) || !Guid.TryParse(request.CrashId, out var id))
        return Results.BadRequest(new { error = "crashId required (guid)" });
    var detail = CrashCatalog.GetDetail(id);
    if (detail is null)
        return Results.NotFound(new { error = "crash not found" });
    if (WebTargetFilter.IsHiddenProject(detail.Summary.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        var layer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
            detail.Summary.Project,
            string.IsNullOrWhiteSpace(request.Tag) ? "crash" : request.Tag!,
            request.Label ?? $"crash {detail.Summary.Id.ToString("N")[..8]}",
            null,
            null,
            null,
            detail.Summary.Id.ToString(),
            detail.Triage?.Summary));
        return Results.Ok(layer);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/stalking/layers/from-corpus", (StalkLayerFromCorpusRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        var layer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
            request.Project,
            string.IsNullOrWhiteSpace(request.Tag) ? "fuzzed" : request.Tag!,
            request.Label ?? $"{request.Tag ?? "fuzzed"} corpus edges",
            null,
            null,
            null,
            null,
            "Imported from data/corpus/<project>/edges.txt",
            request.MiniTimeline));
        return Results.Ok(layer);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapDelete("/api/stalking/{project}/layers/{layerId}", (string project, string layerId) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    return StalkCampaignStore.DeleteLayer(project, layerId) ? Results.NoContent() : Results.NotFound();
});

app.MapGet("/api/stalking/{project}/layers/{layerId}/timeline", (string project, string layerId) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    var layers = StalkCampaignStore.ListLayers(project);
    var layer = layers.FirstOrDefault(l => l.Id.Equals(layerId, StringComparison.OrdinalIgnoreCase));
    if (layer is null)
        return Results.NotFound(new { error = "layer not found" });

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var stalkDir = StalkCampaignStore.ProjectDir(project, repo);
    var key = $"layer-{layer.Id}";
    var existing = MiniTimelineCapture.TryRead(stalkDir, key);
    return existing is not null
        ? Results.Ok(existing)
        : Results.NotFound(new
        {
            error = "No mini-timeline for this layer. Enable fuzz.miniTimelineOnStalk / miniTimeline, or record with miniTimeline: true.",
        });
});

app.MapGet("/api/stalking/{project}/timeline/compare", (string project, string? layers) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    var ids = string.IsNullOrWhiteSpace(layers)
        ? Array.Empty<string>()
        : layers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    return Results.Ok(StalkTimelineCompare.Compare(project, ids));
});

app.MapGet("/api/stalking/{project}/compare", (string project, string? layers) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    var ids = string.IsNullOrWhiteSpace(layers)
        ? Array.Empty<string>()
        : layers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    return Results.Ok(StalkCampaignStore.Compare(project, ids));
});

app.MapGet("/api/stalking/{project}/missed", (string project, int? limit, FuzzSessionManager sessions) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        return Results.Ok(MissedBlockAnalyzer.Analyze(project, limit: limit ?? 80, liveStatus: sessions.Status));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/stalking/{project}/map", (string project, int? limit, string? binary, FuzzSessionManager sessions) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        return Results.Ok(StalkMapBuilder.Build(
            project,
            binaryPath: binary,
            limit: limit ?? 40,
            liveStatus: sessions.Status));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/stalking/{project}/surface", (string project, string? layerId) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    if (!string.IsNullOrWhiteSpace(layerId))
    {
            var one = ExploitSurfaceEngine.TryRead(project, layerId);
        return one is not null
            ? Results.Ok(one)
            : Results.NotFound(new { error = "No surface report for layer — run assess" });
    }

    var latest = ExploitSurfaceEngine.TryReadLatest(project);
    return latest is not null
        ? Results.Ok(latest)
        : Results.NotFound(new
        {
            error = "No exploit-surface report yet. Record a baseline (auto-assess) or: randall surface assess -p " + project,
        });
});

app.MapPost("/api/stalking/{project}/surface/assess", (string project, ExploitSurfaceAssessRequest? body) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        var report = ExploitSurfaceEngine.AssessProject(
            project,
            layerId: body?.LayerId,
            baselineOnly: body?.BaselineOnly == true);
        return Results.Ok(report);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/stalking/{project}/layers/{layerId}/surface", (string project, string layerId) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    var report = ExploitSurfaceEngine.TryRead(project, layerId);
    if (report is not null)
        return Results.Ok(report);
    // On-demand assess if layer exists
    var layer = StalkCampaignStore.ListLayers(project)
        .FirstOrDefault(l => l.Id.Equals(layerId, StringComparison.OrdinalIgnoreCase));
    if (layer is null)
        return Results.NotFound(new { error = "layer not found" });
    return Results.Ok(ExploitSurfaceEngine.AssessLayer(layer));
});

app.MapPost("/api/stalking/{project}/inventory", (string project, StalkInventoryImportBody body) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.BadRequest(new { error = "project not allowed" });
    if (string.IsNullOrWhiteSpace(body.Path))
        return Results.BadRequest(new { error = "path required" });
    try
    {
        return Results.Ok(MissedBlockAnalyzer.ImportInventory(project, body.Path));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/stalking/export", (StalkExportRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(StalkCoverageExport.Export(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/stalking/tools", () => StalkCampaignStore.ProbeTools());

app.MapGet("/api/debug/tools", () => DebuggerTools.Probe());

app.MapPost("/api/debug/open", (DebuggerOpenRequest request) =>
{
    if (request.CrashId is { } id)
    {
        var result = DebuggerSession.OpenCrash(id, request.Kind);
        return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
    }

    if (!string.IsNullOrWhiteSpace(request.DumpPath))
    {
        var result = DebuggerSession.OpenDump(request.DumpPath, request.Kind);
        return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
    }

    return Results.BadRequest(new { error = "crashId or dumpPath required" });
});

app.MapPost("/api/debug/attach", (DebuggerAttachRequest request, FuzzSessionManager sessions) =>
{
    var pid = request.Pid ?? sessions.Status.TargetPid;
    if (pid is null && !string.IsNullOrWhiteSpace(request.Project))
        pid = DebuggerSession.FindProjectPid(request.Project);
    if (pid is null)
        return Results.BadRequest(new { error = "pid, project, or running fuzz target required" });

    var result = DebuggerSession.Attach(pid.Value, request.Kind, request.Go);
    return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
});

app.MapGet("/api/case/ops", () => CaseRecipeEngine.ListOps());

app.MapGet("/api/case/project/{project}", (string project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    var profile = CaseRecipeStore.GetProfile(project);
    return profile is null ? Results.NotFound(new { error = "project not found" }) : Results.Ok(profile);
});

app.MapPost("/api/case/preview", (CasePreviewRequest request) =>
{
    try
    {
        return Results.Ok(CaseRecipeEngine.Preview(request.Steps ?? []));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/save-seed", (CaseSaveSeedRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.SaveSeed(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/save-dict", (CaseSaveDictRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.SaveDict(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/case/load-seed/{project}/{fileName}", (string project, string fileName) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound(new { error = "project not found" });
    try
    {
        return Results.Ok(CaseRecipeStore.LoadSeed(project, fileName));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/import", (CaseImportBytesRequest request) =>
{
    try
    {
        return Results.Ok(CaseRecipeEngine.Import(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/save-raw-seed", (CaseSaveRawSeedRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.SaveRawSeed(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/case/recipes/{project}", (string project) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    try
    {
        return Results.Ok(CaseRecipeStore.ListRecipes(project));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/case/recipes/{project}/{name}", (string project, string name) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.NotFound();
    try
    {
        return Results.Ok(CaseRecipeStore.LoadRecipe(project, name));
    }
    catch (FileNotFoundException)
    {
        return Results.NotFound();
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/recipes", (CaseSaveRecipeRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.SaveRecipe(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/preview-session", (CaseSessionPreviewRequest request) =>
{
    try
    {
        return Results.Ok(CaseRecipeStore.PreviewSession(request.SessionSteps ?? []));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/apply-session", (CaseApplySessionRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.ApplySessionRecipe(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/from-stream", (CaseFromStreamRequest request) =>
{
    if (!string.IsNullOrWhiteSpace(request.Project) && WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.FromStream(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/promote", (CasePromoteRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.PromoteToProtocol(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/idl", (CaseIdlRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.ImportIdl(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// —— Recipe catalog (browsable fuzzing target templates: file formats / protocols / web) ——
app.MapGet("/api/case/catalog", (string? category, string? search) =>
    Results.Ok(new
    {
        count = RecipeCatalog.Count,
        categories = RecipeCatalog.Categories(),
        entries = RecipeCatalog.List(category, search),
    }));

app.MapGet("/api/case/catalog/{id}", (string id) =>
{
    var detail = RecipeCatalog.Get(id);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
});

app.MapPost("/api/case/catalog/instantiate", (RecipeInstantiateRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Id))
        return Results.BadRequest(new { error = "id required" });
    try
    {
        var result = RecipeCatalog.Instantiate(request.Id, request.Name, request.LocalFolder);
        return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/case/packs", () => Results.Ok(CaseRecipeStore.ListPacks()));

app.MapGet("/api/case/packs/{id}", (string id) =>
{
    try
    {
        return Results.Ok(CaseRecipeStore.LoadPack(id));
    }
    catch (FileNotFoundException)
    {
        return Results.NotFound();
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapDelete("/api/case/recipes/{project}/{name}", (string project, string name) =>
{
    if (WebTargetFilter.IsHiddenProject(project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.DeleteRecipe(project, name));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/mutators", (CaseMutatorsRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.SetMutators(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/new-project", (CaseNewProjectRequest request) =>
{
    try
    {
        return Results.Ok(CaseRecipeStore.CreateProject(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/case/update-project", (CaseUpdateProjectRequest request) =>
{
    if (WebTargetFilter.IsHiddenProject(request.Project))
        return Results.BadRequest(new { error = "project not allowed" });
    try
    {
        return Results.Ok(CaseRecipeStore.UpdateProject(request));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/fuzz/status", (FuzzSessionManager sessions) => sessions.Status);

app.MapGet("/api/fuzz/logs", (FuzzLiveLogBuffer liveLog, FuzzSessionManager sessions) =>
{
    var status = sessions.Status;
    return Results.Ok(new
    {
        running = status.Running || status.Phase is "starting" or "running" or "stopping",
        phase = status.Phase,
        logs = liveLog.Snapshot(),
    });
});

app.MapPost("/api/fuzz/start", (
    FuzzStartRequest request,
    FuzzSessionManager sessions,
    SignalRFuzzProgressSink sink) =>
{
    if (string.IsNullOrWhiteSpace(request.ConfigPath))
        return Results.BadRequest(new { error = "configPath required" });
    if (!sessions.Start(request, sink))
        return Results.Conflict(new { error = "A fuzz session is already running" });
    return Results.Accepted("/api/fuzz/status", sessions.Status);
});

app.MapPost("/api/fuzz/stop", (FuzzSessionManager sessions) =>
{
    if (!sessions.Stop())
        return Results.NotFound(new { error = "No active session" });
    return Results.Ok(sessions.Status);
});

app.MapPost("/api/recorders/stop", () =>
{
    // Emergency orphan cleanup — normal Stop already disposes armed bookends in FuzzEngine.
    var result = RecordingTeardown.StopHostCaptures();
    return Results.Ok(result);
});

app.MapGet("/api/proxy/status", (ProxyManager proxy) => proxy.Status);

app.MapGet("/api/proxy/messages", (ProxyManager proxy) =>
    proxy.Messages().Select(m => new CapturedMessageDto(
        m.Id,
        m.Direction,
        m.At,
        m.Data.Length,
        string.Join(' ', m.Data.Take(32).Select(b => b.ToString("X2"))) + (m.Data.Length > 32 ? " …" : ""),
        m.CommandTag)).OrderByDescending(m => m.At));

app.MapGet("/api/proxy/messages/{id:guid}", (Guid id, ProxyManager proxy) =>
{
    var m = proxy.Messages().FirstOrDefault(x => x.Id == id);
    if (m is null)
        return Results.NotFound(new { error = "Message not found" });
    var ascii = new string(m.Data.Select(b => b is >= 32 and <= 126 ? (char)b : '.').ToArray());
    return Results.Ok(new CapturedMessageDetailDto(
        m.Id,
        m.Direction,
        m.At,
        m.Data.Length,
        Convert.ToHexString(m.Data),
        ascii.Length > 256 ? ascii[..256] + "…" : ascii,
        m.CommandTag));
});

app.MapPost("/api/proxy/start", (ProxyStartRequest request, ProxyManager proxy) =>
{
    if (!proxy.Start(request))
        return Results.Conflict(new { error = "Proxy already running" });
    return Results.Ok(proxy.Status);
});

app.MapPost("/api/proxy/stop", async (ProxyManager proxy) =>
{
    await proxy.StopAsync();
    return Results.Ok(proxy.Status);
});

app.MapPost("/api/proxy/replay", async (ProxyReplayRequest request, ProxyManager proxy) =>
{
    var ok = await proxy.ReplayAsync(request.MessageId, request.EditedHex);
    return ok ? Results.Ok(proxy.Status) : Results.NotFound(new { error = "Message not found" });
});

app.MapPost("/api/crashes/{id:guid}/export", (Guid id) =>
{
    var bundle = CrashStalker.ExportBundle(id);
    return bundle is null ? Results.NotFound() : Results.Ok(bundle);
});

app.MapGet("/api/campaign/status", (CampaignSessionManager campaigns) => campaigns.Status);

app.MapPost("/api/campaign/start", (
    CampaignStartRequest request,
    CampaignSessionManager campaigns,
    SignalRFuzzProgressSink sink) =>
{
    if (string.IsNullOrWhiteSpace(request.CampaignPath))
        return Results.BadRequest(new { error = "campaignPath required" });
    if (!campaigns.Start(request.CampaignPath, sink))
        return Results.Conflict(new { error = "Campaign already running" });
    return Results.Accepted("/api/campaign/status", campaigns.Status);
});

app.MapPost("/api/campaign/stop", (CampaignSessionManager campaigns) =>
{
    campaigns.Stop();
    return Results.Ok(campaigns.Status);
});

app.MapPost("/api/bundle/export", (BundleExportRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.ConfigPath))
        return Results.BadRequest(new { error = "configPath required" });
    try
    {
        var path = ProjectBundle.Export(Path.GetFullPath(request.ConfigPath), request.OutputPath);
        var size = new FileInfo(path).Length;
        return Results.Ok(new BundleResultDto(path, "export", size));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/bundle/import", (BundleImportRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.ZipPath))
        return Results.BadRequest(new { error = "zipPath required" });
    try
    {
        var path = ProjectBundle.Import(Path.GetFullPath(request.ZipPath), request.OutputDir);
        return Results.Ok(new BundleResultDto(path, "import", null));
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/api/docs", () => DocsCatalog.List());
app.MapGet("/api/docs/{*path}", (string path) =>
{
    var doc = DocsCatalog.Read(path);
    return doc is null ? Results.NotFound(new { error = "doc not found" }) : Results.Ok(doc);
});

app.MapGet("/api/remote/tools", () => StalkCampaignStore.ProbeTools());
app.MapGet("/api/remote/procmon", () => RemoteStalkAgent.Status());
app.MapPost("/api/remote/procmon/start", (RemoteProcmonStartRequest? request) =>
    Results.Ok(RemoteStalkAgent.Start(request?.BackingFile)));
app.MapPost("/api/remote/procmon/stop", () => Results.Ok(RemoteStalkAgent.Stop()));

app.MapHub<FuzzHub>("/hubs/fuzz");

app.Run();

static IResult ServeRepoAsset(params string[] relatives)
{
    var repoRoot = CrashCatalog.FindRepoRoot();
    if (repoRoot is null)
        return Results.NotFound();
    foreach (var relative in relatives)
    {
        var path = Path.Combine(repoRoot, relative);
        if (!File.Exists(path))
            continue;
        var contentType = Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".webp" => "image/webp",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            _ => "image/png",
        };
        return Results.File(path, contentType);
    }
    return Results.NotFound();
}

sealed record RemoteProcmonStartRequest(string? BackingFile);
sealed record StalkInventoryImportBody(string Path);

static class WebTargetFilter
{
    private static readonly HashSet<string> Hidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "cfpass",
    };

    public static bool IsHiddenProject(string? name) =>
        !string.IsNullOrWhiteSpace(name) && Hidden.Contains(name);

    public static bool IsVisibleProject(string? name) =>
        string.IsNullOrWhiteSpace(name) || !Hidden.Contains(name);

    public static bool IsVisible(TargetProfileDto t) =>
        IsVisibleProject(t.Name) &&
        t.Name.IndexOf("cfpass", StringComparison.OrdinalIgnoreCase) < 0 &&
        t.ConfigPath.IndexOf("cfpass", StringComparison.OrdinalIgnoreCase) < 0;
}
