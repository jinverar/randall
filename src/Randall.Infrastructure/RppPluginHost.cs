using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Randall.Infrastructure;

/// <summary>Leg 8 — Pack: Randall Process Plugin host (Python / Node / Rust over JSON stdin/stdout).</summary>
public sealed class RppPluginHost(string pluginDir)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public string PluginDir { get; } = pluginDir;

    public static RppPluginManifest? LoadManifest(string manifestPath)
    {
        if (!File.Exists(manifestPath))
            return null;
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
        return deserializer.Deserialize<RppPluginManifest>(File.ReadAllText(manifestPath));
    }

    public static IEnumerable<(RppPluginManifest Manifest, string Dir)> Discover(string pluginsDir)
    {
        if (!Directory.Exists(pluginsDir))
            yield break;
        foreach (var dir in Directory.EnumerateDirectories(pluginsDir))
        {
            var manifestPath = Path.Combine(dir, "rpp.yaml");
            var manifest = LoadManifest(manifestPath);
            if (manifest is not null)
                yield return (manifest, dir);
        }
    }

    public async Task<byte[]?> MutateAsync(RppPluginManifest manifest, byte[] input, CancellationToken cancellationToken = default)
    {
        var entry = Path.Combine(PluginDir, manifest.Entry);
        if (!File.Exists(entry))
            return null;

        var exe = ResolveRuntime(manifest.Runtime);
        if (exe is null)
            return null;

        var request = JsonSerializer.Serialize(new
        {
            op = "mutate",
            input = Convert.ToBase64String(input),
        }, JsonOptions);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"\"{entry}\"",
            WorkingDirectory = PluginDir,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = Encoding.UTF8,
            StandardOutputEncoding = Encoding.UTF8,
        };

        using var process = Process.Start(psi);
        if (process is null)
            return null;

        await process.StandardInput.WriteLineAsync(request);
        await process.StandardInput.FlushAsync();
        process.StandardInput.Close();

        var outputLine = await process.StandardOutput.ReadLineAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (string.IsNullOrWhiteSpace(outputLine))
            return null;

        using var doc = JsonDocument.Parse(outputLine);
        if (!doc.RootElement.TryGetProperty("output", out var outProp))
            return null;
        return Convert.FromBase64String(outProp.GetString() ?? "");
    }

    public async Task<RppReceiveResult?> PostReceiveAsync(
        RppPluginManifest manifest,
        byte[] sent,
        byte[]? response,
        CancellationToken cancellationToken = default)
    {
        var entry = Path.Combine(PluginDir, manifest.Entry);
        if (!File.Exists(entry))
            return null;

        var exe = ResolveRuntime(manifest.Runtime);
        if (exe is null)
            return null;

        var request = JsonSerializer.Serialize(new
        {
            op = "post_receive",
            input = Convert.ToBase64String(sent),
            response = response is null ? "" : Convert.ToBase64String(response),
        }, JsonOptions);

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"\"{entry}\"",
            WorkingDirectory = PluginDir,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = Encoding.UTF8,
            StandardOutputEncoding = Encoding.UTF8,
        };

        using var process = Process.Start(psi);
        if (process is null)
            return null;

        await process.StandardInput.WriteLineAsync(request);
        await process.StandardInput.FlushAsync();
        process.StandardInput.Close();

        var outputLine = await process.StandardOutput.ReadLineAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (string.IsNullOrWhiteSpace(outputLine))
            return new RppReceiveResult("continue", null);

        using var doc = JsonDocument.Parse(outputLine);
        var action = doc.RootElement.TryGetProperty("action", out var act)
            ? act.GetString() ?? "continue"
            : "continue";
        string? note = doc.RootElement.TryGetProperty("note", out var noteProp)
            ? noteProp.GetString()
            : null;
        return new RppReceiveResult(action, note);
    }

    public async Task<string?> PostCrashAsync(
        RppPluginManifest manifest,
        byte[] input,
        int? exitCode,
        string detail,
        string? miniDumpPath,
        CancellationToken cancellationToken = default)
    {
        var entry = Path.Combine(PluginDir, manifest.Entry);
        if (!File.Exists(entry))
            return null;

        var exe = ResolveRuntime(manifest.Runtime);
        if (exe is null)
            return null;

        var request = JsonSerializer.Serialize(new
        {
            op = "post_crash",
            input = Convert.ToBase64String(input),
            exitCode,
            detail,
            miniDump = miniDumpPath ?? "",
        }, JsonOptions);

        var outputLine = await InvokePluginAsync(exe, entry, request, cancellationToken);
        if (string.IsNullOrWhiteSpace(outputLine))
            return null;

        using var doc = JsonDocument.Parse(outputLine);
        if (doc.RootElement.TryGetProperty("tag", out var tagProp))
            return tagProp.GetString();
        if (doc.RootElement.TryGetProperty("classification", out var classProp))
            return classProp.GetString();
        return null;
    }

    public async Task<RppObserveResult?> ObserveAsync(
        RppPluginManifest manifest,
        int iteration,
        byte[] input,
        int newEdges,
        int totalEdges,
        string? detail,
        CancellationToken cancellationToken = default)
    {
        var entry = Path.Combine(PluginDir, manifest.Entry);
        if (!File.Exists(entry))
            return null;

        var exe = ResolveRuntime(manifest.Runtime);
        if (exe is null)
            return null;

        var request = JsonSerializer.Serialize(new
        {
            op = "observe",
            iteration,
            input = Convert.ToBase64String(input),
            newEdges,
            totalEdges,
            detail = detail ?? "",
        }, JsonOptions);

        var outputLine = await InvokePluginAsync(exe, entry, request, cancellationToken);
        if (string.IsNullOrWhiteSpace(outputLine))
            return null;

        using var doc = JsonDocument.Parse(outputLine);
        var root = doc.RootElement;

        Observation? observation = null;
        if (root.TryGetProperty("novelty", out var noveltyProp) &&
            noveltyProp.TryGetDouble(out var novelty))
        {
            var confidence = root.TryGetProperty("confidence", out var confProp) && confProp.TryGetDouble(out var c)
                ? c
                : Math.Clamp(newEdges / 5.0, 0, 1);
            var severity = root.TryGetProperty("severity", out var sevProp)
                ? sevProp.GetString() ?? "info"
                : "info";
            string? note = root.TryGetProperty("note", out var noteProp) ? noteProp.GetString() : null;
            observation = new Observation(
                ObservationKind.Generic,
                "",
                confidence,
                novelty,
                severity,
                new Dictionary<string, object?> { ["note"] = note, ["plugin"] = manifest.Name },
                DateTimeOffset.UtcNow,
                iteration);
        }

        FaultSignal? fault = null;
        if (root.TryGetProperty("signal", out var signalProp))
        {
            var signalName = signalProp.GetString() ?? "other";
            var faultConfidence = root.TryGetProperty("confidence", out var fcProp) && fcProp.TryGetDouble(out var fc)
                ? fc
                : 0.6;
            var faultSeverity = root.TryGetProperty("severity", out var fsProp)
                ? fsProp.GetString() ?? "medium"
                : "medium";
            string? note = root.TryGetProperty("note", out var fnProp) ? fnProp.GetString() : null;
            fault = new FaultSignal(
                MapPluginSignal(signalName),
                faultConfidence,
                faultSeverity,
                FaultSignalSource.RppPlugin,
                $"RPP observe: {signalName}",
                note);
        }

        string? responseNote = root.TryGetProperty("note", out var nProp) ? nProp.GetString() : null;
        return new RppObserveResult(manifest.Name, observation, fault, responseNote);
    }

    private static FaultSignalKind MapPluginSignal(string signal) =>
        signal.ToLowerInvariant() switch
        {
            "access_violation" or "av" => FaultSignalKind.AccessViolation,
            "stack_overflow" => FaultSignalKind.StackOverflow,
            "heap" or "heap_corruption" => FaultSignalKind.HeapCorruption,
            "sanitizer" or "asan" => FaultSignalKind.Sanitizer,
            "uaf" or "use_after_free" => FaultSignalKind.UseAfterFree,
            "hang" or "timeout" => FaultSignalKind.Hang,
            _ => FaultSignalKind.Other,
        };

    private async Task<string?> InvokePluginAsync(
        string exe,
        string entry,
        string request,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"\"{entry}\"",
            WorkingDirectory = PluginDir,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = Encoding.UTF8,
            StandardOutputEncoding = Encoding.UTF8,
        };

        using var process = Process.Start(psi);
        if (process is null)
            return null;

        await process.StandardInput.WriteLineAsync(request);
        await process.StandardInput.FlushAsync();
        process.StandardInput.Close();

        var outputLine = await process.StandardOutput.ReadLineAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return outputLine;
    }

    private static string? ResolveRuntime(string runtime) => runtime.ToLowerInvariant() switch
    {
        "python" or "py" => FindOnPath("python.exe") ?? FindOnPath("python3.exe"),
        "node" or "nodejs" => FindOnPath("node.exe"),
        _ => FindOnPath(runtime),
    };

    private static string? FindOnPath(string fileName)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (path is null)
            return null;
        foreach (var dir in path.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), fileName);
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }
}

public sealed record RppReceiveResult(string Action, string? Note);

public sealed class RppMutator(RppPluginHost host, RppPluginManifest manifest) : IMutator
{
    public string Name => $"rpp:{manifest.Name}";

    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        var result = host.MutateAsync(manifest, input.ToArray()).GetAwaiter().GetResult();
        return result ?? input;
    }
}
