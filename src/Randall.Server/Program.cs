using Randall.Contracts;
using Randall.Infrastructure;

const string HtmlShell = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Randall</title>
  <style>
    :root { --bg: #0f1419; --panel: #1a2332; --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --done: #3fb950; --todo: #484f58; }
    * { box-sizing: border-box; }
    body { font-family: "Segoe UI", system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 1.5rem; }
    h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
    .header { display: flex; gap: 1.25rem; align-items: center; margin-bottom: 1.5rem; }
    .mascot { width: 112px; height: auto; border-radius: 8px; border: 1px solid #30363d; flex-shrink: 0; }
    .mascot-banner { margin: 0 0 1.25rem; text-align: center; }
    .mascot-banner img { max-width: 100%; width: 420px; border-radius: 8px; border: 1px solid #30363d; }
    .mascot-banner figcaption { color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }
    .tagline { color: var(--muted); margin: 0; }
    nav { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
    nav button { background: var(--panel); border: 1px solid #30363d; color: var(--text); padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; }
    nav button.active { border-color: var(--accent); color: var(--accent); }
    section { display: none; background: var(--panel); border-radius: 8px; padding: 1.25rem; border: 1px solid #30363d; }
    section.visible { display: block; }
    .phase { margin-bottom: 1.25rem; }
    .phase h3 { margin: 0 0 0.5rem; font-size: 1rem; }
    .phase .status { font-size: 0.75rem; text-transform: uppercase; color: var(--muted); }
    ul.items { list-style: none; padding: 0; margin: 0; }
    ul.items li { padding: 0.35rem 0; display: flex; gap: 0.5rem; align-items: baseline; }
    .check { width: 1rem; color: var(--done); }
    .check.pending { color: var(--todo); }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #30363d; }
    th { color: var(--muted); font-weight: 500; }
    code { background: #0d1117; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85em; }
    .hex { font-family: ui-monospace, monospace; font-size: 0.8rem; word-break: break-all; color: var(--muted); }
    .empty { color: var(--muted); font-style: italic; }
  </style>
</head>
<body>
  <div class="header">
    <img src="/randall.png" alt="Randall — master of mayhem" class="mascot" />
    <div>
      <h1>Randall</h1>
      <p class="tagline">Stalk code paths. Scream on crash.</p>
    </div>
  </div>
  <nav>
    <button type="button" class="active" data-tab="roadmap">Roadmap</button>
    <button type="button" data-tab="targets">Targets</button>
    <button type="button" data-tab="crashes">Crashes</button>
    <button type="button" data-tab="legs">Eight legs</button>
  </nav>

  <section id="roadmap" class="visible"></section>
  <section id="targets"></section>
  <section id="crashes"></section>
  <section id="legs"></section>

  <script>
    const tabs = document.querySelectorAll('nav button');
    const sections = document.querySelectorAll('section');
    tabs.forEach(btn => btn.addEventListener('click', () => {
      tabs.forEach(b => b.classList.remove('active'));
      sections.forEach(s => s.classList.remove('visible'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('visible');
    }));

    fetch('/api/roadmap').then(r => r.json()).then(phases => {
      document.getElementById('roadmap').innerHTML = `
        <figure class="mascot-banner">
          <img src="/randall.png" alt="Randall fuzzing at the console" />
          <figcaption>Master of mayhem. Chaos is my code.</figcaption>
        </figure>` + phases.map(p => `
        <div class="phase">
          <h3>Phase ${p.phase} — ${p.title}</h3>
          <div class="status">${p.status}</div>
          <ul class="items">${p.items.map(i => `
            <li><span class="check ${i.done ? '' : 'pending'}">${i.done ? '✓' : '○'}</span>
              ${i.title}${i.note ? ` <code>${i.note}</code>` : ''}</li>`).join('')}</ul>
        </div>`).join('');
    });

    fetch('/api/targets').then(r => r.json()).then(targets => {
      const el = document.getElementById('targets');
      if (!targets.length) { el.innerHTML = '<p class="empty">No projects in projects/</p>'; return; }
      el.innerHTML = `<table><thead><tr><th>Name</th><th>Kind</th><th>Config</th></tr></thead>
        <tbody>${targets.map(t => `<tr>
          <td><strong>${t.name}</strong><br><span class="hex">${t.description}</span></td>
          <td>${t.kind}</td><td><code>${t.configPath}</code></td></tr>`).join('')}</tbody></table>`;
    });

    fetch('/api/crashes').then(r => r.json()).then(crashes => {
      const el = document.getElementById('crashes');
      if (!crashes.length) {
        el.innerHTML = '<p class="empty">No crashes yet — run <code>randall fuzz -c projects/vulnserver.yaml</code></p>';
        return;
      }
      el.innerHTML = `<table><thead><tr><th>When</th><th>Project</th><th>Iter</th><th>Mutator</th><th>Input</th></tr></thead>
        <tbody>${crashes.map(c => `<tr>
          <td>${new Date(c.observedAt).toLocaleString()}</td>
          <td>${c.project}</td><td>${c.iteration}</td><td>${c.mutator}</td>
          <td><code>${c.inputPath.split(/[/\\]/).pop()}</code>
            ${c.miniDumpPath ? '<br>dump' : ''}</td></tr>`).join('')}</tbody></table>`;
    });

    fetch('/api/legs').then(r => r.json()).then(legs => {
      document.getElementById('legs').innerHTML = `<ul class="items">${legs.map(l =>
        `<li><strong>${l.title}</strong> — ${l.summary}</li>`).join('')}</ul>`;
    });
  </script>
</body>
</html>
""";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();

var app = builder.Build();

app.MapGet("/", () => Results.Content(HtmlShell, "text/html"));

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

app.MapGet("/api/health", () => new HealthDto("Randall", "0.3.0-alpha", "phase-1-complete"));
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

app.Run();
