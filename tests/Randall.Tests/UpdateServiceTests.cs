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
        // Force portable-ish unknown mode without sln — still fine for check.
        try
        {
            var result = await UpdateService.CheckAsync(root, handler);
            Assert.True(result.Ok);
            Assert.True(result.SignatureValid);
            Assert.True(result.UpdateAvailable);
            Assert.True(result.MajorUpdate);
            Assert.Equal("9.9.9", result.LatestVersion);

            var applyNo = await UpdateService.ApplyAsync(confirm: false, root, handler);
            Assert.False(applyNo.Ok);

            var status = UpdateService.Status(root);
            Assert.True(status.UpdateAvailable);
            Assert.True(status.MajorUpdate);
            var dismissed = UpdateService.Dismiss("9.9.9", root);
            Assert.True(dismissed.BannerSuppressed);
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
        Assert.Equal(AppVersion.Version, "0.17.0-alpha");
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
