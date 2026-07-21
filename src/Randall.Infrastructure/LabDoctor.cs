using System.Net.Sockets;
using System.Text;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>Preflight checks before a lab fuzz run — run with <c>randall doctor</c>.</summary>
public static class LabDoctor
{
    public static DoctorReportDto Examine(string yamlPath, bool requireTarget = false, string? platform = null)
    {
        yamlPath = Path.GetFullPath(yamlPath);
        var host = PlatformResolver.Host;
        var resolvedPlatform = PlatformResolver.Resolve(platform);
        var checks = new List<DoctorCheckDto>();
        ProjectConfig? project = null;

        void Add(string id, string status, string message) =>
            checks.Add(new DoctorCheckDto(id, status, message, DoctorCheckPlatform.Classify(id)));

        DoctorReportDto Finish(string projectName, IReadOnlyList<DoctorCheckDto> all)
        {
            var visible = all.Where(c => PlatformScope.VisibleFor(c.Platform, resolvedPlatform)).ToList();
            var ok = !visible.Any(c => c.Status == "fail");
            return new DoctorReportDto(projectName, ok, visible, resolvedPlatform, host);
        }

        if (!File.Exists(yamlPath))
        {
            Add("project", "fail", $"Project file not found: {yamlPath}");
            return Finish(Path.GetFileNameWithoutExtension(yamlPath), checks);
        }

        try
        {
            project = ProjectLoader.Load(yamlPath);
            Add("project", "ok", $"Loaded {project.Name} ({project.Kind})");
        }
        catch (Exception ex)
        {
            Add("project", "fail", ex.Message);
            return Finish(Path.GetFileNameWithoutExtension(yamlPath), checks);
        }

        // Optional external engines (AFL++ / honggfuzz) — fail preflight when selected but missing.
        var engineId = ExternalEngineCampaign.Normalize(project.Fuzz.Engine);
        if (ExternalEngineCampaign.IsExternal(engineId))
        {
            if (!OperatingSystem.IsLinux())
            {
                Add("fuzz.engine", "fail",
                    $"fuzz.engine: {engineId} requires Linux (use randall on Windows, or run the campaign on a Linux VM)");
            }
            else if (!project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                Add("fuzz.engine", "fail",
                    $"fuzz.engine: {engineId} requires kind: file (harness with @@) — see docs/ENGINE_ADAPTERS.md");
            }
            else
            {
                var tool = engineId == ExternalEngineCampaign.EngineAflpp
                    ? LinuxToolPaths.OptionalEngines.First(t => t.Id == "linux:afl")
                    : LinuxToolPaths.OptionalEngines.First(t => t.Id == "linux:honggfuzz");
                var found = LinuxToolPaths.Find(tool);
                Add("fuzz.engine", found is not null ? "ok" : "fail",
                    found is not null
                        ? $"{engineId} → {found}"
                        : $"{tool.Command} not found — {tool.InstallHint} (required for fuzz.engine: {engineId})");
            }
        }
        else if (!engineId.Equals(ExternalEngineCampaign.EngineRandall, StringComparison.Ordinal))
        {
            Add("fuzz.engine", "fail",
                $"Unknown fuzz.engine '{project.Fuzz.Engine}' — use randall | aflpp | honggfuzz");
        }
        else
        {
            Add("fuzz.engine", "ok", "randall (own generation + stalk engine)");
        }

        foreach (var seed in project.Seeds)
        {
            try
            {
                var bytes = ProjectLoader.LoadSeed(yamlPath, seed);
                Add($"seed:{seed}", "ok", $"{bytes.Length} bytes");
            }
            catch (Exception ex)
            {
                Add($"seed:{seed}", "fail", ex.Message);
            }
        }

        if (!string.IsNullOrWhiteSpace(project.Model))
        {
            try
            {
                var model = ProtocolLoader.Load(yamlPath, project.Model);
                var fields = model.GetMutableFields();
                Add("model", "ok", $"{project.Model} — {fields.Count} mutable field(s)");
            }
            catch (Exception ex)
            {
                Add("model", "fail", ex.Message);
            }
        }

        foreach (var cmd in project.SessionCommands)
        {
            if (string.IsNullOrWhiteSpace(cmd.Model))
                continue;
            try
            {
                ProtocolLoader.Load(yamlPath, cmd.Model);
                Add($"protocol:{cmd.Name}", "ok", cmd.Model);
            }
            catch (Exception ex)
            {
                Add($"protocol:{cmd.Name}", "fail", ex.Message);
            }
        }

        var mutators = BuiltInMutators.Create(
            project.Mutators,
            context: new MutationContext { DictionaryTokens = BuiltInMutators.BuildDictionaryTokens(project, yamlPath) });
        Add("mutators", mutators.Count > 0 ? "ok" : "warn",
            string.Join(", ", mutators.Select(m => m.Name)));

        if (!string.IsNullOrWhiteSpace(project.DictionaryFile))
        {
            var dictPath = ProjectLoader.ResolvePath(yamlPath, project.DictionaryFile);
            Add("dictionary", File.Exists(dictPath) ? "ok" : "fail", dictPath);
        }

        var dr = DynamoRioRunner.Discover();
        Add("dynamorio", dr.IsAvailable ? "ok" : "warn",
            dr.IsAvailable
                ? dr.DrrunPath!
                : $"Not found — coverage-guided stalking disabled ({DynamoRioRunner.InstallHint})");

        var stalkMode = (project.Fuzz.StalkMode ?? "auto").Trim().ToLowerInvariant();
        var native = new NativeStalkRunner();
        if (stalkMode == "external" && !dr.IsAvailable)
        {
            Add("stalkMode", "warn", "stalkMode: external but DynamoRIO not found");
        }
        else if (stalkMode == "native" && native.IsAvailable)
        {
            Add("stalkMode", "ok",
                "native PC stalk (debug-event samples) — coarser than DynamoRIO BB coverage");
        }
        else if (stalkMode == "native" && !native.IsAvailable)
        {
            Add("stalkMode", "warn", "stalkMode: native requires Windows");
        }
        else
        {
            var resolved = StalkTraceBackendFactory.ResolveBackendId(project);
            Add("stalkMode", "ok", $"requested={stalkMode}, resolved={resolved}");
        }

        var procmonExe = ProcmonCapture.DiscoverExecutable();
        if (project.Fuzz.ProcmonCapture)
        {
            Add("procmon", procmonExe is not null ? "ok" : "warn",
                procmonExe is not null
                    ? $"ProcmonCapture enabled → {procmonExe}"
                    : "ProcmonCapture enabled but Procmon not found — run scripts/install-recording-tools.ps1");
        }
        else
        {
            Add("procmon", procmonExe is not null ? "ok" : "warn",
                procmonExe is not null
                    ? $"{procmonExe} (set fuzz.procmonCapture: true to bookend runs)"
                    : "Procmon not found — optional .pml bookends disabled (scripts/install-recording-tools.ps1)");
        }

        var tcpvconExe = TcpvconCapture.DiscoverExecutable();
        if (project.Fuzz.TcpvconCapture)
        {
            Add("tcpvcon", tcpvconExe is not null ? "ok" : "warn",
                tcpvconExe is not null
                    ? $"TcpvconCapture enabled → {tcpvconExe}"
                    : "TcpvconCapture enabled but tcpvcon not found — run scripts/install-recording-tools.ps1");
        }
        else
        {
            Add("tcpvcon", tcpvconExe is not null ? "ok" : "warn",
                tcpvconExe is not null
                    ? $"{tcpvconExe} (set fuzz.tcpvconCapture: true for network connection bookends)"
                    : "tcpvcon not found — optional network snapshots disabled (scripts/install-recording-tools.ps1)");
        }

        var procdumpExe = DebuggerTools.FindProcDump();
        if (project.Fuzz.ProcdumpOnCrash)
        {
            var mode = (project.Fuzz.DebuggerMode ?? "none").Trim().ToLowerInvariant();
            if (mode is "wait" or "both" or "attach")
            {
                Add("procdumpOnCrash", "warn",
                    "procdumpOnCrash set but debuggerMode already attaches — ProcDump will be skipped at runtime");
            }
            else
            {
                Add("procdumpOnCrash", procdumpExe is not null ? "ok" : "warn",
                    procdumpExe is not null
                        ? $"ProcdumpOnCrash enabled → {procdumpExe}"
                        : "ProcdumpOnCrash enabled but ProcDump not found — run scripts/install-recording-tools.ps1");
            }
        }
        else
        {
            Add("procdump", procdumpExe is not null ? "ok" : "warn",
                procdumpExe is not null
                    ? $"{procdumpExe} (set fuzz.procdumpOnCrash: true when not using Scream wait)"
                    : "ProcDump not found — optional -e -ma arm disabled (scripts/install-recording-tools.ps1)");
        }

        var pktmonExe = PktmonCapture.DiscoverExecutable();
        var elevated = WindowsElevation.IsProcessElevated();
        if (project.Fuzz.PktmonCapture)
        {
            if (pktmonExe is null)
                Add("pktmon", "warn", "PktmonCapture enabled but pktmon.exe not found");
            else if (!elevated)
                Add("pktmon", "warn",
                    $"PktmonCapture enabled → {pktmonExe} — {WindowsElevation.AdminHint}");
            else
                Add("pktmon", "ok", $"PktmonCapture enabled → {pktmonExe} (elevated)");
        }
        else
        {
            Add("pktmon", pktmonExe is not null ? "ok" : "warn",
                pktmonExe is not null
                    ? $"{pktmonExe} (set fuzz.pktmonCapture: true — needs Admin)"
                    : "pktmon not found — optional packet bookends disabled");
        }

        var tsharkExe = TsharkCapture.DiscoverExecutable();
        if (project.Fuzz.TsharkCapture)
        {
            Add("tshark", tsharkExe is not null ? "ok" : "warn",
                tsharkExe is not null
                    ? $"TsharkCapture enabled → {tsharkExe} (Npcap/admin often required)"
                    : "TsharkCapture enabled but tshark.exe not found — install Wireshark (winget/choco) or place in tools/");
        }
        else
        {
            Add("tshark", tsharkExe is not null ? "ok" : "warn",
                tsharkExe is not null
                    ? $"{tsharkExe} (set fuzz.tsharkCapture: true → fuzz.pcapng; may need Npcap/admin)"
                    : "tshark not found — optional pcap bookends disabled (Wireshark / winget install WiresharkFoundation.Wireshark)");
        }

        var wprExe = EtwCapture.DiscoverExecutable();
        if (project.Fuzz.EtwCapture)
        {
            if (wprExe is null)
                Add("etw", "warn", "EtwCapture enabled but wpr.exe not found");
            else if (!elevated)
                Add("etw", "warn",
                    $"EtwCapture enabled → {wprExe} — {WindowsElevation.AdminHint}");
            else
                Add("etw", "ok", $"EtwCapture enabled → {wprExe} (elevated)");
        }
        else
        {
            Add("etw", wprExe is not null ? "ok" : "warn",
                wprExe is not null
                    ? $"{wprExe} (set fuzz.etwCapture: true for WPR ETL — needs Admin)"
                    : "wpr.exe not found — optional ETW bookends disabled");
        }

        var dbgviewExe = DebugViewCapture.DiscoverExecutable();
        if (project.Fuzz.DebugViewCapture)
        {
            Add("debugView", dbgviewExe is not null ? "ok" : "warn",
                dbgviewExe is not null
                    ? $"DebugViewCapture enabled → {dbgviewExe}"
                    : "DebugViewCapture enabled but Dbgview.exe not found — run scripts/install-recording-tools.ps1");
        }
        else
        {
            Add("debugView", dbgviewExe is not null ? "ok" : "warn",
                dbgviewExe is not null
                    ? $"{dbgviewExe} (set fuzz.debugViewCapture: true for OutputDebugString)"
                    : "Dbgview.exe not found — optional DebugView bookends disabled (scripts/install-recording-tools.ps1)");
        }

        var handleExe = SysinternalsToolPaths.FindHandle();
        var listDllsExe = SysinternalsToolPaths.FindListDlls();
        var pslistExe = SysinternalsToolPaths.FindPsList();
        var sigcheckExe = SysinternalsToolPaths.FindSigCheck();
        var accesschkExe = SysinternalsToolPaths.FindAccessChk();
        var vmmapExe = SysinternalsToolPaths.FindVmMap();
        var coreSnap = new[] { handleExe, listDllsExe, pslistExe }.Count(p => p is not null);
        var extraSnap = new[] { sigcheckExe, accesschkExe, vmmapExe }.Count(p => p is not null);
        if (project.Fuzz.SysinternalsSnapshots)
        {
            Add("sysinternalsSnapshots", coreSnap + extraSnap > 0 ? "ok" : "warn",
                coreSnap + extraSnap > 0
                    ? $"SysinternalsSnapshots enabled → core {coreSnap}/3, extras {extraSnap}/3 (sigcheck/accesschk/vmmap)"
                    : "SysinternalsSnapshots enabled but no Suite CLI tools — run scripts/install-recording-tools.ps1");
        }
        else
        {
            Add("sysinternalsSnapshots", coreSnap + extraSnap > 0 ? "ok" : "warn",
                coreSnap + extraSnap > 0
                    ? $"Sysinternals CLI tools present (core {coreSnap}/3, extras {extraSnap}/3) — set fuzz.sysinternalsSnapshots: true"
                    : "Handle/ListDLLs/PsList not found — optional snapshots disabled (scripts/install-recording-tools.ps1)");
        }

        var stringsExe = SysinternalsToolPaths.FindStrings();
        if (project.Fuzz.StringsOnCrash)
        {
            Add("stringsOnCrash", stringsExe is not null ? "ok" : "warn",
                stringsExe is not null
                    ? $"StringsOnCrash enabled → {stringsExe}"
                    : "StringsOnCrash enabled but strings64.exe not found — run scripts/install-recording-tools.ps1");
        }
        else
        {
            Add("strings", stringsExe is not null ? "ok" : "warn",
                stringsExe is not null
                    ? $"{stringsExe} (set fuzz.stringsOnCrash: true to dump strings on crashing input)"
                    : "strings64.exe not found — optional strings-on-crash disabled (scripts/install-recording-tools.ps1)");
        }

        // Linux fuzzing / triage toolchain — the Unix counterparts to the Windows stack above.
        // Reported on every host so users previewing "linux" from Windows see install hints too.
        foreach (var tool in LinuxToolPaths.Catalog)
        {
            var found = LinuxToolPaths.Find(tool);
            Add(tool.Id, found is not null ? "ok" : "warn",
                found is not null
                    ? $"{found} — {tool.Role}"
                    : $"{tool.Command} not found — {tool.InstallHint} ({tool.Role})");
        }

        // gdb enhancement (GEF preferred) — richer crash inspection on top of gdb.
        var gdbEnhancement = LinuxToolPaths.FindGdbEnhancement();
        Add("linux:gdb-enhance", gdbEnhancement is not null ? "ok" : "warn",
            gdbEnhancement is not null
                ? $"{gdbEnhancement.Kind} active → {gdbEnhancement.Path} (enhanced gdb crash triage)"
                : "no gdb enhancement — install GEF (recommended): bash -c \"$(curl -fsSL https://gef.blah.cat/sh)\" (or pwndbg / peda)");

        // pwntools — exploit-dev library for building/sending payloads and the guided workflow.
        var pwntools = LinuxToolPaths.FindPwntools();
        Add("linux:pwntools", pwntools is not null ? "ok" : "warn",
            pwntools is not null
                ? $"{pwntools} — payload crafting + randall exploit template"
                : "pwntools not found — pip install --user pwntools (exploit scripting)");

        // Heap-corruption detection readiness (tcache poisoning / double-free / UAF / overflow).
        // glibc's built-in tcache hardening is always available on Linux; ASan (clang) + GEF add depth.
        var asanReady = LinuxToolPaths.Find(LinuxToolPaths.Catalog.First(t => t.Id == "linux:clang")) is not null;
        var heapLayers = new List<string> { "glibc malloc.check=3 (tcache double-free/poisoning aborts)" };
        if (asanReady) heapLayers.Add("ASan builds");
        if (gdbEnhancement is not null) heapLayers.Add($"{gdbEnhancement.Kind} heap-analysis");
        Add("linux:heap", "ok",
            $"heap-bug triage ready: {string.Join(" + ", heapLayers)} — classifies tcache/UAF/overflow (randall heaptriage)");

        var dbg = DebuggerTools.Probe();
        foreach (var t in dbg.Tools)
        {
            Add($"debugger:{t.Id}", t.Available ? "ok" : "warn",
                t.Available ? (t.Path ?? t.Name) : $"{t.Name} not found");
        }
        if (!string.IsNullOrWhiteSpace(project.Fuzz.DebuggerMode) &&
            !project.Fuzz.DebuggerMode.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            var mode = project.Fuzz.DebuggerMode.ToLowerInvariant();
            if (mode is "wait" or "both")
                Add("debuggerMode", "ok", "Scream watcher (built-in) will debug-attach for dumps");
            if (mode is "attach" && dbg.PreferredGui is null)
                Add("debuggerMode", "warn", "debuggerMode attach needs WinDbg or WinDbg Preview");
            if (mode is "both" && dbg.PreferredGui is null)
                Add("debuggerMode", "warn", "both opens dumps after crash — install WinDbg Preview for GUI");
            if (!project.Target.LongLived)
                Add("debuggerMode", "warn", "attach/wait work best with target.longLived: true");
        }

        if (!string.IsNullOrWhiteSpace(project.Target.Executable))
        {
            var exe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
            var existing = ExecutableResolver.FindExisting(exe);
            if (existing is not null)
                Add("target", "ok", existing);
            else
                Add("target", requireTarget ? "fail" : "warn",
                    OperatingSystem.IsWindows()
                        ? $"Missing: {exe} — run scripts/build-vulnserver.ps1"
                        : $"Missing: {exe} — build the Linux lab target: scripts/build-lab-targets.sh");
        }
        else if (project.Kind is "tcp" or "udp")
        {
            Add("target", "warn", "No local executable — assumes service already listening");
        }

        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
        {
            var tlsNote = project.Transport.Tls ? "TLS enabled" : "plain TCP";
            Add("transport", "ok", $"{project.Transport.Host}:{project.Transport.Port} ({tlsNote})");
            try
            {
                using var client = new TcpClient();
                var task = client.ConnectAsync(project.Transport.Host, project.Transport.Port);
                if (task.Wait(1500))
                {
                    Add("tcp", "ok", $"{project.Transport.Host}:{project.Transport.Port} reachable");
                    client.Close();
                }
                else
                    Add("tcp", "warn", $"{project.Transport.Host}:{project.Transport.Port} connect timeout");
            }
            catch (Exception ex)
            {
                Add("tcp", "warn", $"{project.Transport.Host}:{project.Transport.Port} — {ex.Message}");
            }
        }

        if (project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var udp = new UdpClient();
                udp.Connect(project.Transport.Host, project.Transport.Port);
                var ping = Encoding.ASCII.GetBytes("RANDALL_PING");
                udp.Send(ping);
                Add("udp", "ok", $"{project.Transport.Host}:{project.Transport.Port} send ok");
            }
            catch (Exception ex)
            {
                Add("udp", "warn", $"{project.Transport.Host}:{project.Transport.Port} — {ex.Message}");
            }
        }

        foreach (var pluginRef in project.Plugins)
        {
            var dir = ProjectLoader.ResolvePath(yamlPath, pluginRef.Path);
            var manifest = RppPluginHost.LoadManifest(Path.Combine(dir, "rpp.yaml"));
            Add($"plugin:{pluginRef.Path}", manifest is not null ? "ok" : "fail",
                manifest?.Name ?? "rpp.yaml missing");
        }

        if (project.SessionGraph is not null)
        {
            var graphReport = SessionGraphValidator.Validate(project, yamlPath);
            var detail = graphReport.Valid
                ? $"start={graphReport.Start}, mutate={graphReport.Mutate}, {project.SessionGraph.Edges.Count} edge(s)"
                : string.Join("; ", graphReport.Errors);
            Add("sessionGraph", graphReport.Valid ? "ok" : "fail", detail);
            foreach (var w in graphReport.Warnings)
                Add("sessionGraph", "warn", w);
        }

        return Finish(project.Name, checks);
    }
}
