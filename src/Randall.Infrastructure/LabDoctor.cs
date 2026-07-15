using System.Net.Sockets;
using System.Text;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>Preflight checks before a lab fuzz run — run with <c>randall doctor</c>.</summary>
public static class LabDoctor
{
    public static DoctorReportDto Examine(string yamlPath, bool requireTarget = false)
    {
        yamlPath = Path.GetFullPath(yamlPath);
        var checks = new List<DoctorCheckDto>();
        ProjectConfig? project = null;

        void Add(string id, string status, string message) =>
            checks.Add(new DoctorCheckDto(id, status, message));

        if (!File.Exists(yamlPath))
        {
            Add("project", "fail", $"Project file not found: {yamlPath}");
            return new DoctorReportDto(Path.GetFileNameWithoutExtension(yamlPath), false, checks);
        }

        try
        {
            project = ProjectLoader.Load(yamlPath);
            Add("project", "ok", $"Loaded {project.Name} ({project.Kind})");
        }
        catch (Exception ex)
        {
            Add("project", "fail", ex.Message);
            return new DoctorReportDto(Path.GetFileNameWithoutExtension(yamlPath), false, checks);
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
            dr.IsAvailable ? dr.DrrunPath! : "Not found — coverage-guided file fuzz disabled");

        if (!string.IsNullOrWhiteSpace(project.Target.Executable))
        {
            var exe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
            if (File.Exists(exe))
                Add("target", "ok", exe);
            else
                Add("target", requireTarget ? "fail" : "warn",
                    $"Missing: {exe} — run scripts/build-vulnserver.ps1");
        }
        else if (project.Kind is "tcp" or "udp")
        {
            Add("target", "warn", "No local executable — assumes service already listening");
        }

        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
        {
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

        var ready = !checks.Any(c => c.Status == "fail");
        return new DoctorReportDto(project.Name, ready, checks);
    }
}
