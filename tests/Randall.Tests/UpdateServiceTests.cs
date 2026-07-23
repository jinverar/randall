using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class UpdateServiceTests
{
    [Fact]
    public void VersionCompare_AndMajorDetection()
    {
        Assert.True(UpdateVersion.IsNewer("0.18.0", "0.17.0-alpha"));
        Assert.False(UpdateVersion.IsNewer("0.16.0", "0.17.0"));
        Assert.True(UpdateVersion.IsMajorUpdate("0.17.0", "1.0.0", "minor"));
        Assert.True(UpdateVersion.IsMajorUpdate("0.17.0", "0.18.0", "major"));
        Assert.False(UpdateVersion.IsMajorUpdate("0.17.0", "0.17.1", "patch"));
    }

    [Fact]
    public void Crypto_Rejects_UnsafeNames_And_Notes()
    {
        Assert.True(UpdateCrypto.IsSafeAssetFileName("randfuzz-linux-x64.zip"));
        Assert.False(UpdateCrypto.IsSafeAssetFileName("../evil.zip"));
        Assert.False(UpdateCrypto.IsSafeAssetFileName("evil.exe"));
        Assert.True(UpdateCrypto.IsSha256Hex(new string('a', 64)));
        Assert.False(UpdateCrypto.IsSha256Hex("deadbeef"));
        Assert.True(UpdateCrypto.IsAllowedNotesUrl("https://github.com/jinverar/randall/releases/tag/v1.0.0"));
        Assert.False(UpdateCrypto.IsAllowedNotesUrl("https://evil.example/notes"));
        Assert.False(UpdateCrypto.IsAllowedNotesUrl("javascript:alert(1)"));
        Assert.True(UpdateCrypto.IsAllowedDiscordWebhook("https://discord.com/api/webhooks/1/abc"));
        Assert.False(UpdateCrypto.IsAllowedDiscordWebhook("https://evil.example/hooks"));
    }

    [Fact]
    public void TrustedGitRemote_Pins_Expected_Repo()
    {
        Assert.True(UpdateService.IsTrustedGitHubRemote("https://github.com/jinverar/randall.git", "jinverar", "randall"));
        Assert.True(UpdateService.IsTrustedGitHubRemote("git@github.com:jinverar/randall.git", "jinverar", "randall"));
        Assert.False(UpdateService.IsTrustedGitHubRemote("https://github.com/evil/randall.git", "jinverar", "randall"));
    }

    [Fact]
    public void SafeExtractZip_Blocks_ZipSlip()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rf-zip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var zipPath = Path.Combine(dir, "slip.zip");
        var staging = Path.Combine(dir, "out");
        Directory.CreateDirectory(staging);
        try
        {
            using (var zs = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var e = zs.CreateEntry("../escape.txt");
                using var w = new StreamWriter(e.Open());
                w.Write("nope");
            }

            Assert.Throws<InvalidOperationException>(() => UpdateService.SafeExtractZip(zipPath, staging));
            Assert.False(File.Exists(Path.Combine(dir, "escape.txt")));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Manifest_RoundTrip_SignAndVerify()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = ecdsa.ExportSubjectPublicKeyInfoPem();
        var priv = ecdsa.ExportPkcs8PrivateKeyPem();
        Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, pub);
        try
        {
            var manifest = new UpdateManifestDto
            {
                Version = "9.9.9",
                Severity = "major",
                NotesUrl = "https://github.com/jinverar/randall/releases/tag/v9.9.9",
                Assets =
                [
                    new UpdateAssetDto
                    {
                        Rid = UpdateService.CurrentRid(),
                        File = "randfuzz-test.zip",
                        Sha256 = UpdateCrypto.Sha256Hex(Encoding.UTF8.GetBytes("payload")),
                        Size = 7,
                    },
                ],
            };
            var json = UpdateService.BuildManifestJson(manifest);
            var sig = UpdateCrypto.SignManifest(json, priv);
            Assert.True(UpdateCrypto.VerifyManifest(json, sig));
            Assert.False(UpdateCrypto.VerifyManifest(json.Replace("9.9.9", "9.9.8"), sig));
            Assert.False(UpdateCrypto.VerifyManifest(json, sig.AsSpan(0, sig.Length - 1).ToArray()));

            // base64 signature form also verifies
            var b64 = Encoding.UTF8.GetBytes(Convert.ToBase64String(sig));
            Assert.True(UpdateCrypto.VerifyManifest(json, b64));
        }
        finally
        {
            Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, null);
        }
    }

    [Fact]
    public async Task CheckAsync_UsesSignedManifest_FromMockGitHub()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = ecdsa.ExportSubjectPublicKeyInfoPem();
        var priv = ecdsa.ExportPkcs8PrivateKeyPem();
        Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, pub);

        var rid = UpdateService.CurrentRid();
        var manifest = new UpdateManifestDto
        {
            Version = "9.9.9",
            Severity = "major",
            Channel = "stable",
            ReleaseTag = "v9.9.9",
            NotesUrl = "https://github.com/jinverar/randall/releases/tag/v9.9.9",
            Assets =
            [
                new UpdateAssetDto
                {
                    Rid = rid,
                    File = $"randfuzz-{rid}.zip",
                    Sha256 = new string('a', 64),
                    Size = 1,
                },
            ],
        };
        var json = UpdateService.BuildManifestJson(manifest);
        var sig = UpdateCrypto.SignManifest(json, priv);

        var releaseJson = JsonSerializer.Serialize(new
        {
            tag_name = "v9.9.9",
            html_url = "https://github.com/jinverar/randall/releases/tag/v9.9.9",
            assets = new object[]
            {
                new
                {
                    name = UpdateService.ManifestName,
                    browser_download_url = "https://github.com/jinverar/randall/releases/download/v9.9.9/update-manifest.json",
                },
                new
                {
                    name = UpdateService.ManifestSigName,
                    browser_download_url = "https://github.com/jinverar/randall/releases/download/v9.9.9/update-manifest.json.sig",
                },
            },
        });

        var handler = new StubHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/releases/latest", StringComparison.Ordinal))
                return Json(releaseJson);
            if (url.EndsWith("update-manifest.json", StringComparison.Ordinal))
                return Text(json);
            if (url.EndsWith("update-manifest.json.sig", StringComparison.Ordinal))
                return Bytes(sig);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var root = Path.Combine(Path.GetTempPath(), "randfuzz-update-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var result = await UpdateService.CheckAsync(root, handler, force: true);
            Assert.True(result.Ok);
            Assert.True(result.SignatureValid);
            Assert.True(result.UpdateAvailable);
            Assert.True(result.MajorUpdate);
            Assert.Equal("9.9.9", result.LatestVersion);
            Assert.Equal(1, result.MatchedAssetSize);

            var applyNo = await UpdateService.ApplyAsync(confirm: false, root, handler);
            Assert.False(applyNo.Ok);

            var status = UpdateService.Status(root);
            Assert.True(status.UpdateAvailable);
            Assert.True(status.MajorUpdate);
            Assert.False(status.BannerSuppressed);
            var dismissed = UpdateService.Dismiss("9.9.9", root);
            Assert.True(dismissed.BannerSuppressed);

            // Cache hit without network when force=false
            var cached = await UpdateService.CheckAsync(root, new StubHandler(_ =>
                new HttpResponseMessage(HttpStatusCode.InternalServerError)), force: false);
            Assert.True(cached.Ok);
            Assert.Contains(cached.Findings ?? [], f => f.Contains("cached", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, null);
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public async Task CheckAsync_Rejects_BadSignature()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, ecdsa.ExportSubjectPublicKeyInfoPem());
        var rid = UpdateService.CurrentRid();
        var manifest = new UpdateManifestDto
        {
            Version = "9.9.9",
            Severity = "major",
            Assets = [new UpdateAssetDto { Rid = rid, File = $"randfuzz-{rid}.zip", Sha256 = new string('b', 64), Size = 1 }],
        };
        var json = UpdateService.BuildManifestJson(manifest);
        var badSig = Encoding.UTF8.GetBytes(new string('x', 128));

        var releaseJson = JsonSerializer.Serialize(new
        {
            tag_name = "v9.9.9",
            html_url = "https://github.com/jinverar/randall/releases/tag/v9.9.9",
            assets = new object[]
            {
                new { name = UpdateService.ManifestName, browser_download_url = "https://github.com/jinverar/randall/releases/download/v9.9.9/update-manifest.json" },
                new { name = UpdateService.ManifestSigName, browser_download_url = "https://github.com/jinverar/randall/releases/download/v9.9.9/update-manifest.json.sig" },
            },
        });

        var handler = new StubHandler(req =>
        {
            var url = req.RequestUri!.ToString();
            if (url.Contains("/releases/latest", StringComparison.Ordinal)) return Json(releaseJson);
            if (url.EndsWith(".json", StringComparison.Ordinal)) return Text(json);
            if (url.EndsWith(".sig", StringComparison.Ordinal)) return Bytes(badSig);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var root = Path.Combine(Path.GetTempPath(), "randfuzz-update-bad-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var result = await UpdateService.CheckAsync(root, handler, force: true);
            Assert.False(result.Ok);
            Assert.False(result.SignatureValid);
            Assert.False(result.UpdateAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable(UpdateCrypto.PubKeyEnv, null);
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void DocsCatalog_IncludesUpdates()
    {
        Assert.Contains(DocsCatalog.Index, i => i.Path == "UPDATES.md");
        Assert.Equal("0.17.0-alpha", AppVersion.Version);
    }

    [Fact]
    public async Task Apply_Refuses_WithoutConfirm()
    {
        var r = await UpdateService.ApplyAsync(confirm: false);
        Assert.False(r.Ok);
        Assert.Contains("confirmation", r.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

    private static HttpResponseMessage Text(string body) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/octet-stream"),
        };

    private static HttpResponseMessage Bytes(byte[] body)
    {
        var msg = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body),
        };
        msg.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return msg;
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
