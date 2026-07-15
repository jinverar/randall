using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();
builder.Services.AddSingleton<FuzzSessionManager>();
builder.Services.AddSingleton<SignalRFuzzProgressSink>();
builder.Services.AddSingleton<ProxyManager>();
builder.Services.AddSingleton<CampaignSessionManager>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/randall.png", () =>
{
    var repoRoot = CrashCatalog.FindRepoRoot();
    if (repoRoot is null)
        return Results.NotFound();
    foreach (var relative in new[] { "docs/assets/randall.png", "randall.png" })
    {
        var path = Path.Combine(repoRoot, relative);
        if (File.Exists(path))
            return Results.File(path, "image/png");
    }
    return Results.NotFound();
});

app.MapGet("/api/health", () => new HealthDto("Randall", "0.7.0-alpha", "leg1-models"));
app.MapGet("/api/plugins", () => PluginCatalog.ListAll());
app.MapGet("/api/protocols", () => ProtocolCatalog.ListAll());
app.MapGet("/api/campaigns", () => PluginCatalog.ListCampaigns());
app.MapGet("/api/legs", () => RandallLegs.All.Select(l => new LegInfoDto(l.Id, l.Title, l.Summary)));
app.MapGet("/api/roadmap", () => RandallRoadmap.Phases);
app.MapGet("/api/targets", () => CrashCatalog.ListTargets());
app.MapGet("/api/crashes", (string? project) => CrashCatalog.ListAll(projectFilter: project));
app.MapGet("/api/crashes/{id:guid}", (Guid id) =>
{
    var detail = CrashCatalog.GetDetail(id);
    return detail is null ? Results.NotFound() : Results.Ok(detail);
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

app.MapGet("/api/fuzz/status", (FuzzSessionManager sessions) => sessions.Status);

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

app.MapGet("/api/proxy/status", (ProxyManager proxy) => proxy.Status);

app.MapGet("/api/proxy/messages", (ProxyManager proxy) =>
    proxy.Messages().Select(m => new CapturedMessageDto(
        m.Id,
        m.Direction,
        m.At,
        m.Data.Length,
        string.Join(' ', m.Data.Take(32).Select(b => b.ToString("X2"))) + (m.Data.Length > 32 ? " …" : ""),
        m.CommandTag)).OrderByDescending(m => m.At));

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

app.MapHub<FuzzHub>("/hubs/fuzz");

app.Run();
