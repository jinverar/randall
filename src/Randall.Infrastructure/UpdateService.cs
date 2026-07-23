using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Secure update check + opt-in apply.
/// Portable packs require a signed <c>update-manifest.json</c> + matching asset SHA-256.
/// Source checkouts can fast-forward to the release tag after the same signature check.
/// </summary>
public static class UpdateService
{
    public const string DefaultOwner = "jinverar";
    public const string DefaultRepo = "randall";
    public const string ManifestName = "update-manifest.json";
    public const string ManifestSigName = "update-manifest.json.sig";
    public const string OwnerRepoEnv = "RANDALL_UPDATE_REPO"; // owner/repo
    public const string ManifestUrlEnv = "RANDALL_UPDATE_MANIFEST_URL";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public enum InstallMode
    {
        Unknown,
        Portable,
        Source,
    }

    public static InstallMode DetectInstallMode(string? root = null)
    {
        root ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        if (File.Exists(Path.Combine(root, "Randall.sln"))
            || File.Exists(Path.Combine(root, "src", "Randall.Cli", "Randall.Cli.csproj")))
            return InstallMode.Source;

        var cliDir = Path.Combine(root, "cli");
        var serverDir = Path.Combine(root, "server");
        if (Directory.Exists(cliDir) && Directory.Exists(serverDir))
            return InstallMode.Portable;

        // Running from packed cli/ — install root is parent.
        var parent = Directory.GetParent(root)?.FullName;
        if (parent is not null
            && Directory.Exists(Path.Combine(parent, "cli"))
            && Directory.Exists(Path.Combine(parent, "server")))
            return InstallMode.Portable;

        return InstallMode.Unknown;
    }

    public static string ResolveInstallRoot(string? hint = null)
    {
        if (!string.IsNullOrWhiteSpace(hint))
            return Path.GetFullPath(hint);

        var root = CrashCatalog.FindRepoRoot();
        if (root is not null)
            return root;

        var cwd = Path.GetFullPath(Directory.GetCurrentDirectory());
        if (Directory.Exists(Path.Combine(cwd, "cli")) && Directory.Exists(Path.Combine(cwd, "server")))
            return cwd;

        var parent = Directory.GetParent(cwd)?.FullName;
        if (parent is not null
            && Directory.Exists(Path.Combine(parent, "cli"))
            && Directory.Exists(Path.Combine(parent, "server")))
            return parent;

        return cwd;
    }

    public static UpdateStatusDto Status(string? installRoot = null)
    {
        var root = ResolveInstallRoot(installRoot);
        var mode = DetectInstallMode(root);
        return UpdateStateStore.ToStatus(UpdateStateStore.Load(root), mode.ToString().ToLowerInvariant());
    }

    public static async Task<UpdateCheckResultDto> CheckAsync(
        string? installRoot = null,
        HttpMessageHandler? handler = null,
        CancellationToken ct = default)
    {
        var root = ResolveInstallRoot(installRoot);
        var mode = DetectInstallMode(root);
        var findings = new List<string>();
        var checkedAt = DateTimeOffset.UtcNow;

        try
        {
            using var http = CreateHttp(handler);
            var (manifestJson, signature, notesUrlHint) = await FetchSignedManifestAsync(http, findings, ct);
            if (manifestJson is null || signature is null)
            {
                var fail = new UpdateCheckResultDto(
                    true,
                    findings.Count > 0
                        ? string.Join(" ", findings)
                        : "No signed update manifest published yet.",
                    AppVersion.Version, null, false, false, false, notesUrlHint, null, null,
                    mode.ToString().ToLowerInvariant(), null, null, checkedAt, findings);
                PersistCheck(root, fail);
                return fail;
            }

            var sigOk = UpdateCrypto.VerifyManifest(manifestJson, signature);
            if (!sigOk)
            {
                findings.Add("Manifest signature verification failed — refusing to trust this release.");
                var fail = new UpdateCheckResultDto(
                    false, "Update manifest signature invalid.", AppVersion.Version, null,
                    false, false, false, notesUrlHint, null, null,
                    mode.ToString().ToLowerInvariant(), null, null, checkedAt, findings);
                PersistCheck(root, fail);
                return fail;
            }

            findings.Add("Manifest signature OK (ECDSA P-256).");
            var manifest = JsonSerializer.Deserialize<UpdateManifestDto>(manifestJson, JsonOpts)
                           ?? throw new InvalidOperationException("Manifest JSON deserialize failed.");

            if (!string.Equals(manifest.Product, "randfuzz", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(manifest.Product, "randall", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add($"Unexpected product id '{manifest.Product}'.");
                var fail = new UpdateCheckResultDto(
                    false, "Manifest product mismatch.", AppVersion.Version, manifest.Version,
                    false, false, true, manifest.NotesUrl ?? notesUrlHint, manifest.Channel, manifest.Severity,
                    mode.ToString().ToLowerInvariant(), null, null, checkedAt, findings);
                PersistCheck(root, fail);
                return fail;
            }

            var available = UpdateVersion.IsNewer(manifest.Version, AppVersion.Version);
            var major = available && UpdateVersion.IsMajorUpdate(AppVersion.Version, manifest.Version, manifest.Severity);
            var rid = CurrentRid();
            var asset = PickAsset(manifest, rid);
            if (available && asset is null)
                findings.Add($"No asset for RID '{rid}' in signed manifest.");

            var msg = !available
                ? $"Up to date ({AppVersion.Version})."
                : major
                    ? $"Major update available: {AppVersion.Version} → {manifest.Version}."
                    : $"Update available: {AppVersion.Version} → {manifest.Version}.";

            var result = new UpdateCheckResultDto(
                true, msg, AppVersion.Version, manifest.Version, available, major, true,
                manifest.NotesUrl ?? notesUrlHint, manifest.Channel, manifest.Severity,
                mode.ToString().ToLowerInvariant(),
                asset?.File, asset?.Sha256, checkedAt, findings);

            PersistCheck(root, result);
            MaybeNotifyMajor(root, result);
            return result;
        }
        catch (Exception ex)
        {
            findings.Add(ex.Message);
            var fail = new UpdateCheckResultDto(
                false, $"Update check failed: {ex.Message}", AppVersion.Version, null,
                false, false, false, null, null, null,
                mode.ToString().ToLowerInvariant(), null, null, checkedAt, findings);
            PersistCheck(root, fail);
            return fail;
        }
    }

    public static async Task<UpdateApplyResultDto> ApplyAsync(
        bool confirm,
        string? installRoot = null,
        HttpMessageHandler? handler = null,
        CancellationToken ct = default)
    {
        var root = ResolveInstallRoot(installRoot);
        var mode = DetectInstallMode(root);
        var steps = new List<string>();

        if (!confirm)
            return new UpdateApplyResultDto(false,
                "Refusing to apply without confirmation. Re-run with --yes (CLI) or confirm=true (API).",
                Steps: steps);

        var check = await CheckAsync(root, handler, ct);
        if (!check.Ok || !check.UpdateAvailable)
            return new UpdateApplyResultDto(false, check.Message, Steps: check.Findings?.ToList() ?? steps);

        if (!check.SignatureValid)
            return new UpdateApplyResultDto(false,
                "Cannot apply: update manifest signature was not verified.",
                Steps: check.Findings?.ToList() ?? steps);

        if (check.MajorUpdate && !confirm)
            return new UpdateApplyResultDto(false, "Major update requires explicit confirmation.", Steps: steps);

        steps.AddRange(check.Findings ?? []);

        return mode switch
        {
            InstallMode.Source => await ApplySourceAsync(root, check, steps, ct),
            InstallMode.Portable => await ApplyPortableAsync(root, check, steps, handler, ct),
            _ => new UpdateApplyResultDto(false,
                "Unknown install layout — expected a git checkout (Randall.sln) or portable pack (cli/ + server/).",
                Steps: steps),
        };
    }

    public static UpdateStatusDto Dismiss(string? version = null, string? installRoot = null)
    {
        var root = ResolveInstallRoot(installRoot);
        var state = UpdateStateStore.Load(root);
        state.DismissedVersion = string.IsNullOrWhiteSpace(version)
            ? state.LastCheckedVersion
            : version.Trim();
        UpdateStateStore.Save(state, root);
        return Status(root);
    }

    public static string BuildManifestJson(UpdateManifestDto manifest) =>
        UpdateCrypto.NormalizeManifestBytes(JsonSerializer.Serialize(manifest, JsonOpts));

    public static (string ManifestJson, byte[] Signature) SignManifestFile(string manifestJson, string privateKeyPem) =>
        (UpdateCrypto.NormalizeManifestBytes(manifestJson), UpdateCrypto.SignManifest(manifestJson, privateKeyPem));

    // —— internals ——

    private static HttpClient CreateHttp(HttpMessageHandler? handler)
    {
        var http = handler is null
            ? new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false, // pin redirects ourselves
                AutomaticDecompression = DecompressionMethods.All,
            })
            : new HttpClient(handler, disposeHandler: false);

        http.Timeout = TimeSpan.FromSeconds(60);
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"Randfuzz/{AppVersion.Version} (+https://github.com/{DefaultOwner}/{DefaultRepo})");
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return http;
    }

    private static async Task<(string? Json, byte[]? Sig, string? NotesUrl)> FetchSignedManifestAsync(
        HttpClient http, List<string> findings, CancellationToken ct)
    {
        var direct = Environment.GetEnvironmentVariable(ManifestUrlEnv);
        if (!string.IsNullOrWhiteSpace(direct))
        {
            findings.Add($"Fetching manifest from {ManifestUrlEnv}.");
            var directJson = await GetTextPinnedAsync(http, direct.Trim(), ct);
            var directSigUrl = direct.Trim().EndsWith(".sig", StringComparison.OrdinalIgnoreCase)
                ? direct.Trim()
                : direct.Trim() + ".sig";
            var directSig = await GetBytesPinnedAsync(http, directSigUrl, ct);
            return (directJson, directSig, null);
        }

        var (owner, repo) = ResolveOwnerRepo();
        var api = $"https://api.github.com/repos/{owner}/{repo}/releases/latest";
        findings.Add($"Querying GitHub releases: {owner}/{repo}.");
        using var resp = await SendPinnedAsync(http, api, ct);
        if (resp.StatusCode == HttpStatusCode.NotFound)
        {
            findings.Add("No GitHub releases published yet.");
            return (null, null, null);
        }

        resp.EnsureSuccessStatusCode();
        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var root = doc.RootElement;
        var tag = root.TryGetProperty("tag_name", out var tagEl) ? tagEl.GetString() : null;
        var htmlUrl = root.TryGetProperty("html_url", out var htmlEl) ? htmlEl.GetString() : null;
        if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        {
            findings.Add($"Release {tag} has no assets (need {ManifestName} + {ManifestSigName}).");
            return (null, null, htmlUrl);
        }

        string? manifestUrl = null;
        string? sigUrl = null;
        foreach (var a in assets.EnumerateArray())
        {
            var name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
            var url = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(url))
                continue;
            if (name.Equals(ManifestName, StringComparison.OrdinalIgnoreCase))
                manifestUrl = url;
            else if (name.Equals(ManifestSigName, StringComparison.OrdinalIgnoreCase))
                sigUrl = url;
        }

        if (manifestUrl is null || sigUrl is null)
        {
            findings.Add($"Release {tag} missing signed manifest assets ({ManifestName} / {ManifestSigName}).");
            return (null, null, htmlUrl);
        }

        var json = await GetTextPinnedAsync(http, manifestUrl, ct);
        var sig = await GetBytesPinnedAsync(http, sigUrl, ct);
        return (json, sig, htmlUrl);
    }

    private static (string Owner, string Repo) ResolveOwnerRepo()
    {
        var env = Environment.GetEnvironmentVariable(OwnerRepoEnv);
        if (!string.IsNullOrWhiteSpace(env))
        {
            var parts = env.Trim().Split('/', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && parts[0].Length > 0 && parts[1].Length > 0)
                return (parts[0], parts[1]);
        }

        return (DefaultOwner, DefaultRepo);
    }

    private static async Task<HttpResponseMessage> SendPinnedAsync(HttpClient http, string url, CancellationToken ct)
    {
        // Follow a small number of redirects, but only to allowlisted hosts.
        var current = url;
        for (var hop = 0; hop < 5; hop++)
        {
            EnsureAllowedUrl(current);
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if ((int)resp.StatusCode is >= 300 and < 400)
            {
                var loc = resp.Headers.Location?.ToString();
                resp.Dispose();
                if (string.IsNullOrWhiteSpace(loc))
                    throw new InvalidOperationException("Redirect without Location.");
                current = new Uri(new Uri(current), loc).ToString();
                continue;
            }

            return resp;
        }

        throw new InvalidOperationException("Too many redirects while fetching update assets.");
    }

    private static async Task<string> GetTextPinnedAsync(HttpClient http, string url, CancellationToken ct)
    {
        using var resp = await SendPinnedAsync(http, url, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync(ct);
    }

    private static async Task<byte[]> GetBytesPinnedAsync(HttpClient http, string url, CancellationToken ct)
    {
        using var resp = await SendPinnedAsync(http, url, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsByteArrayAsync(ct);
    }

    private static void EnsureAllowedUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException($"Refusing non-HTTPS update URL: {url}");

        var host = uri.Host.ToLowerInvariant();
        var allowed =
            host is "github.com" or "api.github.com" or "objects.githubusercontent.com" or "release-assets.githubusercontent.com"
            || host.EndsWith(".githubusercontent.com", StringComparison.Ordinal);
        if (!allowed)
            throw new InvalidOperationException($"Refusing update host '{host}' (allowlist: GitHub only).");
    }

    private static UpdateAssetDto? PickAsset(UpdateManifestDto manifest, string rid)
    {
        return manifest.Assets.FirstOrDefault(a =>
                   a.Rid.Equals(rid, StringComparison.OrdinalIgnoreCase))
               ?? manifest.Assets.FirstOrDefault(a =>
                   a.File.Contains(rid, StringComparison.OrdinalIgnoreCase));
    }

    public static string CurrentRid()
    {
        if (OperatingSystem.IsWindows())
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "win-arm64" : "win-x64";
        if (OperatingSystem.IsMacOS())
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64";
        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "linux-arm64" : "linux-x64";
    }

    private static void PersistCheck(string root, UpdateCheckResultDto result)
    {
        var state = UpdateStateStore.Load(root);
        state.LastCheckedAt = result.CheckedAt;
        state.LastCheckedVersion = result.LatestVersion;
        state.UpdateAvailable = result.UpdateAvailable;
        state.MajorUpdate = result.MajorUpdate;
        state.SignatureValid = result.SignatureValid;
        state.NotesUrl = result.NotesUrl;
        state.Channel = result.Channel;
        state.Severity = result.Severity;
        state.Message = result.Message;
        state.MatchedAssetFile = result.MatchedAssetFile;
        state.MatchedAssetSha256 = result.MatchedAssetSha256;
        UpdateStateStore.Save(state, root);
    }

    private static void MaybeNotifyMajor(string root, UpdateCheckResultDto result)
    {
        if (!result.MajorUpdate || string.IsNullOrWhiteSpace(result.LatestVersion))
            return;

        var state = UpdateStateStore.Load(root);
        if (string.Equals(state.LastMajorNotifiedVersion, result.LatestVersion, StringComparison.OrdinalIgnoreCase))
            return;

        // Best-effort Discord webhook if configured globally (no project yaml required).
        try
        {
            var webhook = NotificationSettings.ResolveDiscordWebhook(null);
            if (string.IsNullOrWhiteSpace(webhook))
            {
                state.LastMajorNotifiedVersion = result.LatestVersion;
                UpdateStateStore.Save(state, root);
                return;
            }

            var body = new
            {
                content = $"**Randfuzz major update** `{result.CurrentVersion}` → `{result.LatestVersion}`\n" +
                          $"{result.NotesUrl}\n" +
                          "Apply when ready: `randall update apply --yes`",
            };
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            http.PostAsync(webhook, content).GetAwaiter().GetResult();
        }
        catch
        {
            /* notification is best-effort */
        }

        state = UpdateStateStore.Load(root);
        state.LastMajorNotifiedVersion = result.LatestVersion;
        UpdateStateStore.Save(state, root);
    }

    private static async Task<UpdateApplyResultDto> ApplySourceAsync(
        string root, UpdateCheckResultDto check, List<string> steps, CancellationToken ct)
    {
        var tag = check.LatestVersion!.StartsWith('v') ? check.LatestVersion : "v" + check.LatestVersion;
        // Prefer exact release tag; fall back to normalized.
        steps.Add($"Source install: fetching tags and fast-forwarding to {tag}.");

        var fetch = await RunGitAsync(root, ["fetch", "--tags", "--force", "origin"], ct);
        steps.Add(fetch.Output.Trim());
        if (fetch.ExitCode != 0)
            return new UpdateApplyResultDto(false, "git fetch failed — update aborted.", check.LatestVersion, Steps: steps);

        var merge = await RunGitAsync(root, ["merge", "--ff-only", tag], ct);
        if (merge.ExitCode != 0)
        {
            // Try without v prefix mismatch
            var alt = tag.StartsWith('v') ? tag[1..] : "v" + tag;
            merge = await RunGitAsync(root, ["merge", "--ff-only", alt], ct);
        }

        steps.Add(merge.Output.Trim());
        if (merge.ExitCode != 0)
            return new UpdateApplyResultDto(false,
                $"git merge --ff-only failed (dirty tree or non-ff?). Resolve manually, then retry.\n{merge.Output}",
                check.LatestVersion, Steps: steps);

        steps.Add("Building solution…");
        var build = await RunProcessAsync("dotnet", ["build", Path.Combine(root, "Randall.sln"), "-c", "Release"], root, ct);
        steps.Add(build.Output.Trim());
        if (build.ExitCode != 0)
            return new UpdateApplyResultDto(false, "dotnet build failed after git update.", check.LatestVersion, Steps: steps);

        return new UpdateApplyResultDto(true,
            $"Updated source tree to {check.LatestVersion} and built Release.",
            check.LatestVersion, RestartRequired: true, Steps: steps);
    }

    private static async Task<UpdateApplyResultDto> ApplyPortableAsync(
        string root,
        UpdateCheckResultDto check,
        List<string> steps,
        HttpMessageHandler? handler,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(check.MatchedAssetFile) || string.IsNullOrWhiteSpace(check.MatchedAssetSha256))
            return new UpdateApplyResultDto(false,
                "Signed manifest has no asset for this RID — cannot apply portable update.",
                check.LatestVersion, Steps: steps);

        using var http = CreateHttp(handler);
        var (owner, repo) = ResolveOwnerRepo();
        var api = $"https://api.github.com/repos/{owner}/{repo}/releases/latest";
        using var rel = await SendPinnedAsync(http, api, ct);
        rel.EnsureSuccessStatusCode();
        await using var stream = await rel.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        string? assetUrl = null;
        foreach (var a in doc.RootElement.GetProperty("assets").EnumerateArray())
        {
            var name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (name is not null && name.Equals(check.MatchedAssetFile, StringComparison.OrdinalIgnoreCase))
            {
                assetUrl = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(assetUrl))
            return new UpdateApplyResultDto(false,
                $"Release asset '{check.MatchedAssetFile}' not found on GitHub.",
                check.LatestVersion, Steps: steps);

        var updatesDir = Path.Combine(root, "data", "updates");
        Directory.CreateDirectory(updatesDir);
        var zipPath = Path.Combine(updatesDir, check.MatchedAssetFile!);
        steps.Add($"Downloading {check.MatchedAssetFile}…");

        using (var dl = await SendPinnedAsync(http, assetUrl, ct))
        {
            dl.EnsureSuccessStatusCode();
            await using var fs = File.Create(zipPath);
            await dl.Content.CopyToAsync(fs, ct);
        }

        await using (var fs = File.OpenRead(zipPath))
        {
            var hex = UpdateCrypto.Sha256Hex(fs);
            if (!UpdateCrypto.FixedHexEquals(hex, check.MatchedAssetSha256))
            {
                try { File.Delete(zipPath); } catch { /* ignore */ }
                return new UpdateApplyResultDto(false,
                    $"SHA-256 mismatch for {check.MatchedAssetFile} (got {hex}, expected {check.MatchedAssetSha256}).",
                    check.LatestVersion, Steps: steps);
            }
        }

        steps.Add("SHA-256 verified.");
        var staging = Path.Combine(updatesDir, "staging-" + Sanitize(check.LatestVersion!));
        if (Directory.Exists(staging))
            Directory.Delete(staging, recursive: true);
        Directory.CreateDirectory(staging);
        ZipFile.ExtractToDirectory(zipPath, staging);
        steps.Add($"Extracted to {staging}");

        // If the zip contains a single top-level folder, descend into it.
        var payload = staging;
        var top = Directory.GetDirectories(staging);
        var topFiles = Directory.GetFiles(staging);
        if (top.Length == 1 && topFiles.Length == 0)
            payload = top[0];

        if (!Directory.Exists(Path.Combine(payload, "cli")) || !Directory.Exists(Path.Combine(payload, "server")))
            return new UpdateApplyResultDto(false,
                "Portable zip layout unexpected — need cli/ and server/ after extract.",
                check.LatestVersion, StagingPath: staging, Steps: steps);

        // Preserve local state: do not overwrite data/ or targets/ from the pack.
        CopyTreeReplace(Path.Combine(payload, "projects"), Path.Combine(root, "projects"), steps);
        CopyTreeReplace(Path.Combine(payload, "docs"), Path.Combine(root, "docs"), steps, optional: true);
        CopyTreeReplace(Path.Combine(payload, "campaigns"), Path.Combine(root, "campaigns"), steps, optional: true);
        CopyTreeReplace(Path.Combine(payload, "plugins"), Path.Combine(root, "plugins"), steps, optional: true);

        var finishScript = WriteFinishScript(root, payload, check.LatestVersion!);
        steps.Add($"Wrote finish script: {finishScript}");
        steps.Add("Launching finish script (replaces cli/ + server/ after this process exits)…");

        LaunchFinishScript(finishScript);
        return new UpdateApplyResultDto(true,
            $"Portable update {check.LatestVersion} staged. cli/server will swap via finish script — restart Randfuzz when it completes.",
            check.LatestVersion, staging, finishScript, RestartRequired: true, steps);
    }

    private static void CopyTreeReplace(string src, string dest, List<string> steps, bool optional = false)
    {
        if (!Directory.Exists(src))
        {
            if (!optional)
                steps.Add($"Missing {src}");
            return;
        }

        Directory.CreateDirectory(dest);
        foreach (var file in Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, file);
            var target = Path.Combine(dest, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }

        steps.Add($"Updated {Path.GetFileName(dest)}/");
    }

    private static string WriteFinishScript(string root, string payload, string version)
    {
        var updatesDir = Path.Combine(root, "data", "updates");
        Directory.CreateDirectory(updatesDir);
        var cliSrc = Path.Combine(payload, "cli");
        var serverSrc = Path.Combine(payload, "server");
        var cliDst = Path.Combine(root, "cli");
        var serverDst = Path.Combine(root, "server");

        if (OperatingSystem.IsWindows())
        {
            var path = Path.Combine(updatesDir, "finish-update.cmd");
            var body = $"""
                @echo off
                rem Randfuzz portable finish-update for {version}
                timeout /t 2 /nobreak >nul
                robocopy "{cliSrc}" "{cliDst}" /MIR /NFL /NDL /NJH /NJS /nc /ns /np >nul
                robocopy "{serverSrc}" "{serverDst}" /MIR /NFL /NDL /NJH /NJS /nc /ns /np >nul
                echo Randfuzz update {version} applied.
                """;
            File.WriteAllText(path, body);
            return path;
        }
        else
        {
            var path = Path.Combine(updatesDir, "finish-update.sh");
            var body =
                "#!/usr/bin/env bash\n" +
                "set -euo pipefail\n" +
                $"# Randfuzz portable finish-update for {version}\n" +
                "sleep 2\n" +
                $"rsync -a --delete \"{cliSrc}/\" \"{cliDst}/\" 2>/dev/null || cp -a \"{cliSrc}/.\" \"{cliDst}/\"\n" +
                $"rsync -a --delete \"{serverSrc}/\" \"{serverDst}/\" 2>/dev/null || cp -a \"{serverSrc}/.\" \"{serverDst}/\"\n" +
                $"echo \"Randfuzz update {version} applied.\"\n";
            File.WriteAllText(path, body);
            try
            {
#pragma warning disable CA1416
                File.SetUnixFileMode(path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
            }
            catch { /* best-effort */ }
            return path;
        }
    }

    private static void LaunchFinishScript(string scriptPath)
    {
        if (OperatingSystem.IsWindows())
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C \"{scriptPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        else
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"\"{scriptPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
    }

    private static string Sanitize(string version)
    {
        var sb = new StringBuilder(version.Length);
        foreach (var ch in version)
            sb.Append(char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '_');
        return sb.ToString();
    }

    private static Task<(int ExitCode, string Output)> RunGitAsync(string cwd, string[] args, CancellationToken ct) =>
        RunProcessAsync("git", args, cwd, ct);

    private static async Task<(int ExitCode, string Output)> RunProcessAsync(
        string file, string[] args, string cwd, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = file,
            WorkingDirectory = cwd,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {file}");
        var stdout = await p.StandardOutput.ReadToEndAsync(ct);
        var stderr = await p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        var combined = (stdout + "\n" + stderr).Trim();
        return (p.ExitCode, combined);
    }
}
