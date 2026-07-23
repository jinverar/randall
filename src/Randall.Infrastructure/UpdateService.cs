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
/// Source checkouts fast-forward to the release tag only after signature check + origin pin.
/// </summary>
public static class UpdateService
{
    public const string DefaultOwner = "jinverar";
    public const string DefaultRepo = "randall";
    public const string ManifestName = "update-manifest.json";
    public const string ManifestSigName = "update-manifest.json.sig";
    public const string OwnerRepoEnv = "RANDALL_UPDATE_REPO"; // owner/repo
    public const string ManifestUrlEnv = "RANDALL_UPDATE_MANIFEST_URL";
    public static readonly TimeSpan DefaultCacheTtl = TimeSpan.FromHours(1);

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

        if (Directory.Exists(Path.Combine(root, "cli")) && Directory.Exists(Path.Combine(root, "server")))
            return InstallMode.Portable;

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
        bool force = false,
        CancellationToken ct = default)
    {
        var root = ResolveInstallRoot(installRoot);
        var mode = DetectInstallMode(root);
        var findings = new List<string>();
        var checkedAt = DateTimeOffset.UtcNow;

        if (!force)
        {
            var cached = TryCachedCheck(root, mode, findings);
            if (cached is not null)
                return cached;
        }

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
                    AppVersion.Version, null, false, false, false, SanitizeNotesUrl(notesUrlHint), null, null,
                    mode.ToString().ToLowerInvariant(), null, null, null, checkedAt, findings);
                PersistCheck(root, fail);
                return fail;
            }

            if (Encoding.UTF8.GetByteCount(manifestJson) > UpdateCrypto.MaxManifestBytes)
            {
                findings.Add("Manifest exceeds size limit — refusing.");
                return FailClosed(root, mode, checkedAt, findings, "Update manifest too large.", notesUrlHint);
            }

            if (signature.Length > UpdateCrypto.MaxSignatureBytes)
            {
                findings.Add("Signature exceeds size limit — refusing.");
                return FailClosed(root, mode, checkedAt, findings, "Update signature too large.", notesUrlHint);
            }

            var sigOk = UpdateCrypto.VerifyManifest(manifestJson, signature);
            if (!sigOk)
            {
                findings.Add("Manifest signature verification failed — refusing to trust this release.");
                return FailClosed(root, mode, checkedAt, findings, "Update manifest signature invalid.", notesUrlHint);
            }

            findings.Add("Manifest signature OK (ECDSA P-256).");
            var manifest = JsonSerializer.Deserialize<UpdateManifestDto>(manifestJson, JsonOpts)
                           ?? throw new InvalidOperationException("Manifest JSON deserialize failed.");

            var validationError = ValidateManifest(manifest, findings);
            if (validationError is not null)
                return FailClosed(root, mode, checkedAt, findings, validationError, manifest.NotesUrl ?? notesUrlHint);

            var available = UpdateVersion.IsNewer(manifest.Version, AppVersion.Version);
            var major = available && UpdateVersion.IsMajorUpdate(AppVersion.Version, manifest.Version, manifest.Severity);
            var rid = CurrentRid();
            var asset = PickAsset(manifest, rid);
            if (available && asset is null)
                findings.Add($"No asset for RID '{rid}' in signed manifest.");

            if (asset is not null && !ValidateAsset(asset, findings))
                asset = null;

            var notes = SanitizeNotesUrl(manifest.NotesUrl) ?? SanitizeNotesUrl(notesUrlHint);
            var msg = !available
                ? $"Up to date ({AppVersion.Version})."
                : major
                    ? $"Major update available: {AppVersion.Version} → {manifest.Version}."
                    : $"Update available: {AppVersion.Version} → {manifest.Version}.";

            var result = new UpdateCheckResultDto(
                true, msg, AppVersion.Version, manifest.Version, available, major, true,
                notes, manifest.Channel, manifest.Severity,
                mode.ToString().ToLowerInvariant(),
                asset?.File, asset?.Sha256, asset?.Size > 0 ? asset.Size : null,
                checkedAt, findings);

            PersistCheck(root, result, manifest.ReleaseTag);
            MaybeNotifyMajor(root, result);
            return result;
        }
        catch (Exception ex)
        {
            findings.Add(ex.Message);
            return FailClosed(root, mode, checkedAt, findings, $"Update check failed: {ex.Message}", null);
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

        using var applyLock = TryAcquireApplyLock(root, out var lockError);
        if (applyLock is null)
            return new UpdateApplyResultDto(false, lockError ?? "Another update apply is already running.", Steps: steps);

        var check = await CheckAsync(root, handler, force: true, ct);
        if (!check.Ok || !check.UpdateAvailable)
            return new UpdateApplyResultDto(false, check.Message, Steps: check.Findings?.ToList() ?? steps);

        if (!check.SignatureValid)
            return new UpdateApplyResultDto(false,
                "Cannot apply: update manifest signature was not verified.",
                Steps: check.Findings?.ToList() ?? steps);

        if (string.IsNullOrWhiteSpace(check.LatestVersion) || !UpdateCrypto.IsSafeVersion(check.LatestVersion))
            return new UpdateApplyResultDto(false, "Cannot apply: release version failed validation.", Steps: steps);

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
        var target = string.IsNullOrWhiteSpace(version) ? state.LastCheckedVersion : version.Trim();
        if (!string.IsNullOrWhiteSpace(target) && !UpdateCrypto.IsSafeVersion(target))
            return Status(root);
        state.DismissedVersion = target;
        UpdateStateStore.Save(state, root);
        return Status(root);
    }

    public static string BuildManifestJson(UpdateManifestDto manifest) =>
        UpdateCrypto.NormalizeManifestBytes(JsonSerializer.Serialize(manifest, JsonOpts));

    public static (string ManifestJson, byte[] Signature) SignManifestFile(string manifestJson, string privateKeyPem)
    {
        var normalized = UpdateCrypto.NormalizeManifestBytes(manifestJson);
        return (normalized, UpdateCrypto.SignManifest(normalized, privateKeyPem));
    }

    public static string CurrentRid()
    {
        if (OperatingSystem.IsWindows())
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "win-arm64" : "win-x64";
        if (OperatingSystem.IsMacOS())
            return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64";
        return RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "linux-arm64" : "linux-x64";
    }

    // —— internals ——

    private static UpdateCheckResultDto? TryCachedCheck(string root, InstallMode mode, List<string> findings)
    {
        var state = UpdateStateStore.Load(root);
        if (state.LastCheckedAt is null)
            return null;
        if (DateTimeOffset.UtcNow - state.LastCheckedAt.Value > DefaultCacheTtl)
            return null;
        // Only reuse successful signature-valid results (or clean "no update / no manifest").
        if (state.UpdateAvailable && !state.SignatureValid)
            return null;

        findings.Add($"Using cached check from {state.LastCheckedAt:u} (pass --force to refresh).");
        return new UpdateCheckResultDto(
            true,
            state.Message ?? "Cached update status.",
            AppVersion.Version,
            state.LastCheckedVersion,
            state.UpdateAvailable,
            state.MajorUpdate,
            state.SignatureValid,
            SanitizeNotesUrl(state.NotesUrl),
            state.Channel,
            state.Severity,
            mode.ToString().ToLowerInvariant(),
            state.MatchedAssetFile,
            state.MatchedAssetSha256,
            state.MatchedAssetSize,
            state.LastCheckedAt.Value,
            findings);
    }

    private static UpdateCheckResultDto FailClosed(
        string root,
        InstallMode mode,
        DateTimeOffset checkedAt,
        List<string> findings,
        string message,
        string? notesUrl)
    {
        var fail = new UpdateCheckResultDto(
            false, message, AppVersion.Version, null,
            false, false, false, SanitizeNotesUrl(notesUrl), null, null,
            mode.ToString().ToLowerInvariant(), null, null, null, checkedAt, findings);
        PersistCheck(root, fail);
        return fail;
    }

    private static string? ValidateManifest(UpdateManifestDto manifest, List<string> findings)
    {
        if (manifest.SchemaVersion is < 1 or > 1)
        {
            findings.Add($"Unsupported manifest schemaVersion {manifest.SchemaVersion}.");
            return "Unsupported update manifest schema.";
        }

        if (!string.Equals(manifest.Product, "randfuzz", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(manifest.Product, "randall", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add($"Unexpected product id '{manifest.Product}'.");
            return "Manifest product mismatch.";
        }

        if (!UpdateCrypto.IsSafeVersion(manifest.Version))
        {
            findings.Add("Manifest version failed format checks.");
            return "Manifest version invalid.";
        }

        var channel = (manifest.Channel ?? "stable").Trim().ToLowerInvariant();
        if (channel is not ("stable" or "beta" or "rc"))
        {
            findings.Add($"Refusing channel '{manifest.Channel}'.");
            return "Manifest channel not allowed.";
        }

        var severity = (manifest.Severity ?? "minor").Trim().ToLowerInvariant();
        if (severity is not ("major" or "minor" or "patch"))
        {
            findings.Add($"Refusing severity '{manifest.Severity}'.");
            return "Manifest severity not allowed.";
        }

        if (!string.IsNullOrWhiteSpace(manifest.NotesUrl) && !UpdateCrypto.IsAllowedNotesUrl(manifest.NotesUrl))
        {
            findings.Add("Manifest notesUrl is not an https://github.com/… URL — ignoring link.");
            manifest.NotesUrl = null;
        }

        if (!string.IsNullOrWhiteSpace(manifest.ReleaseTag))
        {
            var tag = manifest.ReleaseTag.Trim();
            var expected = manifest.Version.StartsWith('v') ? manifest.Version : "v" + manifest.Version.TrimStart('v', 'V');
            var alt = expected.StartsWith('v') ? expected[1..] : expected;
            if (!tag.Equals(expected, StringComparison.OrdinalIgnoreCase)
                && !tag.Equals(alt, StringComparison.OrdinalIgnoreCase)
                && !tag.Equals("v" + alt, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add($"ReleaseTag '{tag}' does not match version '{manifest.Version}'.");
                return "Manifest releaseTag mismatch.";
            }
        }

        if (manifest.Assets.Count == 0)
        {
            findings.Add("Manifest has no assets.");
            return "Manifest has no assets.";
        }

        return null;
    }

    private static bool ValidateAsset(UpdateAssetDto asset, List<string> findings)
    {
        if (!UpdateCrypto.IsSafeAssetFileName(asset.File))
        {
            findings.Add($"Asset file name rejected: '{asset.File}'.");
            return false;
        }

        if (!UpdateCrypto.IsSha256Hex(asset.Sha256))
        {
            findings.Add($"Asset SHA-256 rejected for '{asset.File}'.");
            return false;
        }

        if (asset.Size < 0 || asset.Size > UpdateCrypto.MaxAssetBytes)
        {
            findings.Add($"Asset size out of bounds for '{asset.File}'.");
            return false;
        }

        return true;
    }

    private static string? SanitizeNotesUrl(string? url) =>
        UpdateCrypto.IsAllowedNotesUrl(url) ? url!.Trim() : null;

    private static HttpClient CreateHttp(HttpMessageHandler? handler)
    {
        var http = handler is null
            ? new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.All,
            })
            : new HttpClient(handler, disposeHandler: false);

        http.Timeout = TimeSpan.FromSeconds(90);
        http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"Randfuzz/{AppVersion.Version} (+https://github.com/{DefaultOwner}/{DefaultRepo})");
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
            EnsureAllowedUrl(direct.Trim());
            var directJson = await GetTextPinnedAsync(http, direct.Trim(), UpdateCrypto.MaxManifestBytes, ct);
            var directSigUrl = direct.Trim().EndsWith(".sig", StringComparison.OrdinalIgnoreCase)
                ? direct.Trim()
                : direct.Trim() + ".sig";
            EnsureAllowedUrl(directSigUrl);
            var directSig = await GetBytesPinnedAsync(http, directSigUrl, UpdateCrypto.MaxSignatureBytes, ct);
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
        var releaseBody = await ReadCappedStringAsync(resp, UpdateCrypto.MaxManifestBytes, ct);
        using var doc = JsonDocument.Parse(releaseBody);
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

        var json = await GetTextPinnedAsync(http, manifestUrl, UpdateCrypto.MaxManifestBytes, ct);
        var sig = await GetBytesPinnedAsync(http, sigUrl, UpdateCrypto.MaxSignatureBytes, ct);
        return (json, sig, htmlUrl);
    }

    private static (string Owner, string Repo) ResolveOwnerRepo()
    {
        var env = Environment.GetEnvironmentVariable(OwnerRepoEnv);
        if (!string.IsNullOrWhiteSpace(env))
        {
            var parts = env.Trim().Split('/', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2
                && IsSafeRepoToken(parts[0])
                && IsSafeRepoToken(parts[1]))
                return (parts[0], parts[1]);
        }

        return (DefaultOwner, DefaultRepo);
    }

    private static bool IsSafeRepoToken(string value) =>
        value.Length is >= 1 and <= 100
        && value.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '.');

    private static async Task<HttpResponseMessage> SendPinnedAsync(HttpClient http, string url, CancellationToken ct)
    {
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

    private static async Task<string> GetTextPinnedAsync(HttpClient http, string url, int maxBytes, CancellationToken ct)
    {
        using var resp = await SendPinnedAsync(http, url, ct);
        resp.EnsureSuccessStatusCode();
        return await ReadCappedStringAsync(resp, maxBytes, ct);
    }

    private static async Task<byte[]> GetBytesPinnedAsync(HttpClient http, string url, int maxBytes, CancellationToken ct)
    {
        using var resp = await SendPinnedAsync(http, url, ct);
        resp.EnsureSuccessStatusCode();
        return await ReadCappedBytesAsync(resp, maxBytes, ct);
    }

    private static async Task<string> ReadCappedStringAsync(HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        var bytes = await ReadCappedBytesAsync(resp, maxBytes, ct);
        return Encoding.UTF8.GetString(bytes);
    }

    private static async Task<byte[]> ReadCappedBytesAsync(HttpResponseMessage resp, int maxBytes, CancellationToken ct)
    {
        if (resp.Content.Headers.ContentLength is long cl && cl > maxBytes)
            throw new InvalidOperationException($"Remote content length {cl} exceeds limit {maxBytes}.");

        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        long total = 0;
        while (true)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
            if (n <= 0)
                break;
            total += n;
            if (total > maxBytes)
                throw new InvalidOperationException($"Remote content exceeded size limit ({maxBytes} bytes).");
            ms.Write(buffer, 0, n);
        }

        return ms.ToArray();
    }

    private static void EnsureAllowedUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException($"Refusing non-HTTPS update URL: {url}");

        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException("Refusing update URL with embedded credentials.");

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
                   !string.IsNullOrWhiteSpace(a.File)
                   && a.File.Contains(rid, StringComparison.OrdinalIgnoreCase));
    }

    private static void PersistCheck(string root, UpdateCheckResultDto result, string? releaseTag = null)
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
        state.MatchedAssetSize = result.MatchedAssetSize;
        state.ReleaseTag = releaseTag;
        UpdateStateStore.Save(state, root);
    }

    private static void MaybeNotifyMajor(string root, UpdateCheckResultDto result)
    {
        if (!result.MajorUpdate || !result.SignatureValid || string.IsNullOrWhiteSpace(result.LatestVersion))
            return;

        var state = UpdateStateStore.Load(root);
        if (string.Equals(state.LastMajorNotifiedVersion, result.LatestVersion, StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            var webhook = NotificationSettings.ResolveDiscordWebhook(null);
            if (!string.IsNullOrWhiteSpace(webhook) && UpdateCrypto.IsAllowedDiscordWebhook(webhook))
            {
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
        var remoteCheck = await EnsureTrustedGitOriginAsync(root, steps, ct);
        if (remoteCheck is not null)
            return remoteCheck;

        var tag = PreferReleaseTag(root, check.LatestVersion!);
        steps.Add($"Source install: fetching tags and fast-forwarding to {tag}.");

        var fetch = await RunGitAsync(root, ["fetch", "--tags", "origin"], ct);
        steps.Add(TrimOutput(fetch.Output));
        if (fetch.ExitCode != 0)
            return new UpdateApplyResultDto(false, "git fetch failed — update aborted.", check.LatestVersion, Steps: steps);

        var merge = await RunGitAsync(root, ["merge", "--ff-only", tag], ct);
        if (merge.ExitCode != 0)
        {
            var alt = tag.StartsWith('v') ? tag[1..] : "v" + tag;
            merge = await RunGitAsync(root, ["merge", "--ff-only", alt], ct);
        }

        steps.Add(TrimOutput(merge.Output));
        if (merge.ExitCode != 0)
            return new UpdateApplyResultDto(false,
                $"git merge --ff-only failed (dirty tree or non-ff?). Resolve manually, then retry.\n{TrimOutput(merge.Output)}",
                check.LatestVersion, Steps: steps);

        steps.Add("Building solution…");
        var build = await RunProcessAsync("dotnet", ["build", Path.Combine(root, "Randall.sln"), "-c", "Release"], root, ct);
        steps.Add(TrimOutput(build.Output));
        if (build.ExitCode != 0)
            return new UpdateApplyResultDto(false, "dotnet build failed after git update.", check.LatestVersion, Steps: steps);

        return new UpdateApplyResultDto(true,
            $"Updated source tree to {check.LatestVersion} and built Release.",
            check.LatestVersion, RestartRequired: true, Steps: steps);
    }

    private static string PreferReleaseTag(string root, string version)
    {
        var state = UpdateStateStore.Load(root);
        if (!string.IsNullOrWhiteSpace(state.ReleaseTag) && UpdateCrypto.IsSafeVersion(state.ReleaseTag.TrimStart('v', 'V')))
            return state.ReleaseTag!.StartsWith('v') ? state.ReleaseTag : "v" + state.ReleaseTag;
        return version.StartsWith('v') ? version : "v" + version;
    }

    private static async Task<UpdateApplyResultDto?> EnsureTrustedGitOriginAsync(
        string root, List<string> steps, CancellationToken ct)
    {
        var (owner, repo) = ResolveOwnerRepo();
        var remote = await RunGitAsync(root, ["remote", "get-url", "origin"], ct);
        if (remote.ExitCode != 0 || string.IsNullOrWhiteSpace(remote.Output))
            return new UpdateApplyResultDto(false, "Cannot read git remote 'origin' — aborting source update.", Steps: steps);

        var url = remote.Output.Trim();
        steps.Add($"origin = {url}");
        if (!IsTrustedGitHubRemote(url, owner, repo))
            return new UpdateApplyResultDto(false,
                $"Refusing source update: origin is not https://github.com/{owner}/{repo} (or matching SSH). Got: {url}",
                Steps: steps);
        return null;
    }

    public static bool IsTrustedGitHubRemote(string url, string owner, string repo)
    {
        var u = url.Trim();
        var https = $"https://github.com/{owner}/{repo}";
        var httpsGit = https + ".git";
        var ssh = $"git@github.com:{owner}/{repo}";
        var sshGit = ssh + ".git";
        var sshAlt = $"ssh://git@github.com/{owner}/{repo}";
        var sshAltGit = sshAlt + ".git";
        return u.Equals(https, StringComparison.OrdinalIgnoreCase)
               || u.Equals(httpsGit, StringComparison.OrdinalIgnoreCase)
               || u.Equals(ssh, StringComparison.OrdinalIgnoreCase)
               || u.Equals(sshGit, StringComparison.OrdinalIgnoreCase)
               || u.Equals(sshAlt, StringComparison.OrdinalIgnoreCase)
               || u.Equals(sshAltGit, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<UpdateApplyResultDto> ApplyPortableAsync(
        string root,
        UpdateCheckResultDto check,
        List<string> steps,
        HttpMessageHandler? handler,
        CancellationToken ct)
    {
        if (!UpdateCrypto.IsSafeAssetFileName(check.MatchedAssetFile)
            || !UpdateCrypto.IsSha256Hex(check.MatchedAssetSha256))
            return new UpdateApplyResultDto(false,
                "Signed manifest has no valid asset for this RID — cannot apply portable update.",
                check.LatestVersion, Steps: steps);

        using var http = CreateHttp(handler);
        var (owner, repo) = ResolveOwnerRepo();
        var api = $"https://api.github.com/repos/{owner}/{repo}/releases/latest";
        using var rel = await SendPinnedAsync(http, api, ct);
        rel.EnsureSuccessStatusCode();
        var releaseBody = await ReadCappedStringAsync(rel, UpdateCrypto.MaxManifestBytes, ct);
        using var doc = JsonDocument.Parse(releaseBody);
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

        var maxBytes = check.MatchedAssetSize is > 0 and <= UpdateCrypto.MaxAssetBytes
            ? check.MatchedAssetSize.Value
            : UpdateCrypto.MaxAssetBytes;

        using (var dl = await SendPinnedAsync(http, assetUrl, ct))
        {
            dl.EnsureSuccessStatusCode();
            await using var fs = File.Create(zipPath);
            await CopyCappedAsync(dl.Content, fs, maxBytes, ct);
        }

        long actualSize;
        await using (var fs = File.OpenRead(zipPath))
        {
            actualSize = fs.Length;
            var hex = UpdateCrypto.Sha256Hex(fs);
            if (!UpdateCrypto.FixedHexEquals(hex, check.MatchedAssetSha256))
            {
                try { File.Delete(zipPath); } catch { /* ignore */ }
                return new UpdateApplyResultDto(false,
                    $"SHA-256 mismatch for {check.MatchedAssetFile} (got {hex}, expected {check.MatchedAssetSha256}).",
                    check.LatestVersion, Steps: steps);
            }
        }

        if (check.MatchedAssetSize is > 0 && check.MatchedAssetSize != actualSize)
        {
            try { File.Delete(zipPath); } catch { /* ignore */ }
            return new UpdateApplyResultDto(false,
                $"Size mismatch for {check.MatchedAssetFile} (got {actualSize}, expected {check.MatchedAssetSize}).",
                check.LatestVersion, Steps: steps);
        }

        steps.Add("SHA-256 verified.");
        var staging = Path.Combine(updatesDir, "staging-" + Sanitize(check.LatestVersion!));
        if (Directory.Exists(staging))
            Directory.Delete(staging, recursive: true);
        Directory.CreateDirectory(staging);

        try
        {
            SafeExtractZip(zipPath, staging, steps);
        }
        catch (Exception ex)
        {
            try { Directory.Delete(staging, true); } catch { /* ignore */ }
            return new UpdateApplyResultDto(false, $"Zip extract refused: {ex.Message}", check.LatestVersion, Steps: steps);
        }

        steps.Add($"Extracted to {staging}");

        var payload = staging;
        var top = Directory.GetDirectories(staging);
        var topFiles = Directory.GetFiles(staging);
        if (top.Length == 1 && topFiles.Length == 0)
            payload = top[0];

        if (!Directory.Exists(Path.Combine(payload, "cli")) || !Directory.Exists(Path.Combine(payload, "server")))
            return new UpdateApplyResultDto(false,
                "Portable zip layout unexpected — need cli/ and server/ after extract.",
                check.LatestVersion, StagingPath: staging, Steps: steps);

        // Preserve local state: never touch data/, targets/, or projects/local/.
        CopyTreeReplace(Path.Combine(payload, "projects"), Path.Combine(root, "projects"), steps, skipLocal: true);
        CopyTreeReplace(Path.Combine(payload, "docs"), Path.Combine(root, "docs"), steps, optional: true);
        CopyTreeReplace(Path.Combine(payload, "campaigns"), Path.Combine(root, "campaigns"), steps, optional: true);
        CopyTreeReplace(Path.Combine(payload, "plugins"), Path.Combine(root, "plugins"), steps, optional: true);

        var finishScript = WriteFinishScript(root, payload, check.LatestVersion!);
        steps.Add($"Wrote finish script: {finishScript}");
        steps.Add("Launching finish script (replaces cli/ + server/ after a short delay)…");

        LaunchFinishScript(finishScript);
        return new UpdateApplyResultDto(true,
            $"Portable update {check.LatestVersion} staged. cli/server will swap via finish script — restart Randfuzz when it completes.",
            check.LatestVersion, staging, finishScript, RestartRequired: true, steps);
    }

    /// <summary>Zip-slip safe extract: every entry must stay under <paramref name="destDir"/>.</summary>
    public static void SafeExtractZip(string zipPath, string destDir, List<string>? steps = null)
    {
        destDir = Path.GetFullPath(destDir);
        Directory.CreateDirectory(destDir);
        using var archive = ZipFile.OpenRead(zipPath);
        long totalUncompressed = 0;
        const long maxTotalUncompressed = UpdateCrypto.MaxAssetBytes * 2;

        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name) && (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\')))
                continue; // directory marker

            if (entry.FullName.Contains("..", StringComparison.Ordinal)
                || Path.IsPathRooted(entry.FullName)
                || entry.FullName.Contains(':', StringComparison.Ordinal))
                throw new InvalidOperationException($"Zip entry path rejected: {entry.FullName}");

            totalUncompressed += entry.Length;
            if (totalUncompressed > maxTotalUncompressed)
                throw new InvalidOperationException("Zip uncompressed size exceeds limit.");

            var target = Path.GetFullPath(Path.Combine(destDir, entry.FullName));
            if (!target.StartsWith(destDir + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !target.Equals(destDir, StringComparison.Ordinal))
                throw new InvalidOperationException($"Zip-slip blocked: {entry.FullName}");

            var dir = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            if (string.IsNullOrEmpty(entry.Name))
                continue;

            entry.ExtractToFile(target, overwrite: true);
        }

        steps?.Add($"Safe-extracted {archive.Entries.Count} zip entries.");
    }

    private static void CopyTreeReplace(
        string src,
        string dest,
        List<string> steps,
        bool optional = false,
        bool skipLocal = false)
    {
        if (!Directory.Exists(src))
        {
            if (!optional)
                steps.Add($"Missing {src}");
            return;
        }

        dest = Path.GetFullPath(dest);
        Directory.CreateDirectory(dest);
        foreach (var file in Directory.EnumerateFiles(src, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, file);
            if (skipLocal && (rel.StartsWith("local" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                              || rel.StartsWith("local/", StringComparison.OrdinalIgnoreCase)
                              || rel.Equals("local", StringComparison.OrdinalIgnoreCase)))
                continue;

            if (rel.Contains("..", StringComparison.Ordinal))
                throw new InvalidOperationException($"Refusing path traversal in pack file: {rel}");

            var target = Path.GetFullPath(Path.Combine(dest, rel));
            if (!target.StartsWith(dest + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !target.Equals(dest, StringComparison.Ordinal))
                throw new InvalidOperationException($"Refusing copy outside destination: {rel}");

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }

        steps.Add($"Updated {Path.GetFileName(dest)}/" + (skipLocal ? " (preserved projects/local)" : ""));
    }

    private static string WriteFinishScript(string root, string payload, string version)
    {
        var updatesDir = Path.Combine(root, "data", "updates");
        Directory.CreateDirectory(updatesDir);
        var safeVersion = Sanitize(version);
        var cliSrc = Path.GetFullPath(Path.Combine(payload, "cli"));
        var serverSrc = Path.GetFullPath(Path.Combine(payload, "server"));
        var cliDst = Path.GetFullPath(Path.Combine(root, "cli"));
        var serverDst = Path.GetFullPath(Path.Combine(root, "server"));

        // Ensure sources stay under the install tree's updates staging area.
        var stagingRoot = Path.GetFullPath(updatesDir);
        if (!cliSrc.StartsWith(stagingRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || !serverSrc.StartsWith(stagingRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidOperationException("Finish script sources must stay under data/updates staging.");

        if (OperatingSystem.IsWindows())
        {
            var path = Path.Combine(updatesDir, "finish-update.cmd");
            var body = $"""
                @echo off
                rem Randfuzz portable finish-update for {safeVersion}
                timeout /t 2 /nobreak >nul
                robocopy "{cliSrc}" "{cliDst}" /E /NFL /NDL /NJH /NJS /nc /ns /np >nul
                robocopy "{serverSrc}" "{serverDst}" /E /NFL /NDL /NJH /NJS /nc /ns /np >nul
                echo Randfuzz update {safeVersion} applied.
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
                $"# Randfuzz portable finish-update for {safeVersion}\n" +
                "sleep 2\n" +
                $"mkdir -p \"{cliDst}\" \"{serverDst}\"\n" +
                $"cp -a \"{cliSrc}/.\" \"{cliDst}/\"\n" +
                $"cp -a \"{serverSrc}/.\" \"{serverDst}/\"\n" +
                $"echo \"Randfuzz update {safeVersion} applied.\"\n";
            File.WriteAllText(path, body);
            try
            {
#pragma warning disable CA1416
                File.SetUnixFileMode(path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
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
                ArgumentList = { "/C", scriptPath },
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        else
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "/bin/bash",
                ArgumentList = { scriptPath },
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
    }

    private static FileStream? TryAcquireApplyLock(string root, out string? error)
    {
        error = null;
        try
        {
            var dir = Path.Combine(root, "data", "updates");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, ".apply.lock");
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            error = "Another update apply is already in progress (lock busy).";
            return null;
        }
        catch (Exception ex)
        {
            error = "Could not acquire update apply lock: " + ex.Message;
            return null;
        }
    }

    private static async Task CopyCappedAsync(HttpContent content, Stream dest, long maxBytes, CancellationToken ct)
    {
        if (content.Headers.ContentLength is long cl && cl > maxBytes)
            throw new InvalidOperationException($"Download Content-Length {cl} exceeds limit {maxBytes}.");

        await using var src = await content.ReadAsStreamAsync(ct);
        var buffer = new byte[81920];
        long total = 0;
        while (true)
        {
            var n = await src.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
            if (n <= 0)
                break;
            total += n;
            if (total > maxBytes)
                throw new InvalidOperationException($"Download exceeded size limit ({maxBytes} bytes).");
            await dest.WriteAsync(buffer.AsMemory(0, n), ct);
        }
    }

    private static string Sanitize(string version)
    {
        var sb = new StringBuilder(version.Length);
        foreach (var ch in version)
            sb.Append(char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '_');
        return sb.ToString();
    }

    private static string TrimOutput(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return "";
        var t = output.Trim();
        return t.Length <= 2000 ? t : t[..2000] + "…";
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
        return (p.ExitCode, (stdout + "\n" + stderr).Trim());
    }
}
