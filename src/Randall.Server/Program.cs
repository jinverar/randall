using Randall.Contracts;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();

var app = builder.Build();

app.MapGet("/", () => Results.Content("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>Randall</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
        h1 { margin-bottom: 0.25rem; }
        .tagline { opacity: 0.75; margin-bottom: 1.5rem; }
        ol li { margin: 0.5rem 0; }
        code { background: #f4f4f4; padding: 0.1rem 0.35rem; border-radius: 4px; }
      </style>
    </head>
    <body>
      <h1>Randall</h1>
      <p class="tagline">Stalk code paths. Scream on crash.</p>
      <p>Eight legs — eight fuzzing concepts. API: <code>/api/legs</code>, <code>/api/health</code></p>
      <ol id="legs"></ol>
      <script>
        fetch('/api/legs').then(r => r.json()).then(legs => {
          document.getElementById('legs').innerHTML = legs.map(l =>
            `<li><strong>${l.title}</strong> — ${l.summary}</li>`).join('');
        });
      </script>
    </body>
    </html>
    """, "text/html"));

app.MapGet("/api/health", () => new HealthDto("Randall", "0.1.0-alpha", "scaffolding"));
app.MapGet("/api/legs", () => RandallLegs.All.Select(l => new LegInfoDto(l.Id, l.Title, l.Summary)));
app.MapGet("/api/crashes", () => Array.Empty<CrashSummaryDto>());

app.Run();
