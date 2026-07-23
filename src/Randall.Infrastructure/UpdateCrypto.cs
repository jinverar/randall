using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// ECDSA P-256 (SHA-256) verification for update manifests.
/// Public key is embedded; override with env <c>RANDALL_UPDATE_PUBKEY_PEM</c> for lab/testing.
/// </summary>
public static partial class UpdateCrypto
{
    public const string PubKeyEnv = "RANDALL_UPDATE_PUBKEY_PEM";
    public const string SignKeyEnv = "RANDALL_UPDATE_SIGNING_KEY_PEM";

    public const int MaxManifestBytes = 256 * 1024;
    public const int MaxSignatureBytes = 8 * 1024;
    public const long MaxAssetBytes = 512L * 1024 * 1024; // 512 MiB

    /// <summary>Official Randfuzz update-manifest verify key (SPKI PEM).</summary>
    public const string EmbeddedPublicKeyPem =
        """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERDyt77nhPEfNBrDy09hknz6KfsmM
        6NAqHWLl5eHyOoPltoWk0i/HfAyffjK6TKz2LB4wfT8w0kgugi7wAKfaBw==
        -----END PUBLIC KEY-----
        """;

    public static string ResolvePublicKeyPem()
    {
        var env = Environment.GetEnvironmentVariable(PubKeyEnv);
        if (!string.IsNullOrWhiteSpace(env))
        {
            var t = env.Trim();
            if (t.Contains("BEGIN", StringComparison.Ordinal))
                return NormalizePem(t);
            return NormalizePem(
                "-----BEGIN PUBLIC KEY-----\n" + t + "\n-----END PUBLIC KEY-----");
        }

        return NormalizePem(EmbeddedPublicKeyPem);
    }

    public static bool VerifyManifest(string manifestJson, byte[] signature)
    {
        try
        {
            var sig = DecodeSignature(signature);
            if (sig.Length is < 64 or > 256)
                return false;

            using var ecdsa = LoadPublicKey(ResolvePublicKeyPem());
            var data = Encoding.UTF8.GetBytes(NormalizeManifestBytes(manifestJson));
            return ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    public static byte[] SignManifest(string manifestJson, string privateKeyPem)
    {
        using var ecdsa = LoadPrivateKey(privateKeyPem);
        var data = Encoding.UTF8.GetBytes(NormalizeManifestBytes(manifestJson));
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    /// <summary>Accept raw DER/IEEE-P1363 signatures or base64 / base64url text.</summary>
    public static byte[] DecodeSignature(byte[] raw)
    {
        if (raw.Length == 0)
            return raw;

        // ASCII base64/base64url text (common for .sig files checked in as text).
        // Check this BEFORE the length-64/96 heuristic — base64 of a 64-byte P1363
        // sig is 88 chars, but base64 of DER is often ~96 chars and would be
        // misclassified as raw P1363 on Windows.
        if (LooksLikeBase64Text(raw))
        {
            try
            {
                var text = Encoding.UTF8.GetString(raw).Trim();
                text = text.Replace('-', '+').Replace('_', '/');
                switch (text.Length % 4)
                {
                    case 2: text += "=="; break;
                    case 3: text += "="; break;
                }
                return Convert.FromBase64String(text);
            }
            catch
            {
                /* fall through to raw */
            }
        }

        return raw;
    }

    private static bool LooksLikeBase64Text(byte[] raw)
    {
        if (raw.Length < 16)
            return false;
        // Reject obvious DER (SEQUENCE tag) as binary.
        if (raw[0] == 0x30)
            return false;
        for (var i = 0; i < raw.Length; i++)
        {
            var b = raw[i];
            if (b is >= (byte)'A' and <= (byte)'Z') continue;
            if (b is >= (byte)'a' and <= (byte)'z') continue;
            if (b is >= (byte)'0' and <= (byte)'9') continue;
            if (b is (byte)'+' or (byte)'/' or (byte)'=' or (byte)'-' or (byte)'_') continue;
            if (b is (byte)'\r' or (byte)'\n' or (byte)' ' or (byte)'\t') continue;
            return false;
        }
        return true;
    }

    public static string Sha256Hex(Stream stream)
    {
        if (stream.CanSeek)
            stream.Position = 0;
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static bool FixedHexEquals(string? a, string? b)
    {
        if (!IsSha256Hex(a) || !IsSha256Hex(b))
            return false;
        var aa = Convert.FromHexString(a!.Trim());
        var bb = Convert.FromHexString(b!.Trim());
        return CryptographicOperations.FixedTimeEquals(aa, bb);
    }

    public static bool IsSha256Hex(string? value) =>
        !string.IsNullOrWhiteSpace(value) && Sha256HexRegex().IsMatch(value.Trim());

    /// <summary>Basename only — no separators, no traversal.</summary>
    public static bool IsSafeAssetFileName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;
        var n = name.Trim();
        if (n.Length is < 1 or > 180)
            return false;
        if (n is "." or ".." || n.Contains('/') || n.Contains('\\') || n.Contains(':'))
            return false;
        return AssetNameRegex().IsMatch(n);
    }

    public static bool IsSafeVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return false;
        var v = version.Trim().TrimStart('v', 'V');
        return SafeVersionRegex().IsMatch(v);
    }

    public static bool IsAllowedNotesUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme != Uri.UriSchemeHttps)
            return false;
        var host = uri.Host.ToLowerInvariant();
        return host is "github.com" or "www.github.com";
    }

    public static bool IsAllowedDiscordWebhook(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme != Uri.UriSchemeHttps)
            return false;
        var host = uri.Host.ToLowerInvariant();
        return host is "discord.com" or "discordapp.com"
               || host.EndsWith(".discord.com", StringComparison.Ordinal)
               || host.EndsWith(".discordapp.com", StringComparison.Ordinal);
    }

    /// <summary>Strip BOM / normalize newlines so signed bytes are stable.</summary>
    public static string NormalizeManifestBytes(string json)
    {
        var s = json.Trim().TrimStart('\uFEFF').Replace("\r\n", "\n").Replace('\r', '\n');
        if (!s.EndsWith('\n'))
            s += "\n";
        return s;
    }

    public static string NormalizePem(string pem)
    {
        var lines = pem.Replace("\r\n", "\n").Replace('\r', '\n').Trim().Split('\n');
        return string.Join("\n", lines.Select(l => l.Trim())).Trim() + "\n";
    }

    private static ECDsa LoadPublicKey(string pem)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }

    private static ECDsa LoadPrivateKey(string pem)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }

    [GeneratedRegex(@"^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256HexRegex();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._+-]*\.(zip|json)$")]
    private static partial Regex AssetNameRegex();

    [GeneratedRegex(@"^\d+\.\d+(\.\d+)?([.-][A-Za-z0-9.-]+)?$")]
    private static partial Regex SafeVersionRegex();
}

/// <summary>Parse / compare SemVer-ish product versions (suffixes ignored for ordering).</summary>
public static partial class UpdateVersion
{
    public readonly record struct Parts(int Major, int Minor, int Patch, string Raw);

    public static Parts Parse(string? version)
    {
        var raw = (version ?? "").Trim().TrimStart('v', 'V');
        if (string.IsNullOrEmpty(raw))
            return new Parts(0, 0, 0, "");

        var core = raw.Split('-', 2)[0].Split('+', 2)[0];
        var m = SemVerRegex().Match(core);
        if (!m.Success)
            return new Parts(0, 0, 0, raw);

        return new Parts(
            int.Parse(m.Groups[1].Value),
            int.Parse(m.Groups[2].Value),
            m.Groups[3].Success ? int.Parse(m.Groups[3].Value) : 0,
            raw);
    }

    public static int Compare(string? a, string? b)
    {
        var pa = Parse(a);
        var pb = Parse(b);
        var c = pa.Major.CompareTo(pb.Major);
        if (c != 0) return c;
        c = pa.Minor.CompareTo(pb.Minor);
        if (c != 0) return c;
        return pa.Patch.CompareTo(pb.Patch);
    }

    public static bool IsNewer(string? candidate, string? current) =>
        Compare(candidate, current) > 0;

    /// <summary>
    /// Major notification: SemVer major bump, or releaser severity=major.
    /// </summary>
    public static bool IsMajorUpdate(string? current, string? latest, string? severity)
    {
        if (!IsNewer(latest, current))
            return false;
        if (string.Equals(severity, "major", StringComparison.OrdinalIgnoreCase))
            return true;

        var c = Parse(current);
        var l = Parse(latest);
        return l.Major > c.Major;
    }

    [GeneratedRegex(@"^(\d+)\.(\d+)(?:\.(\d+))?$")]
    private static partial Regex SemVerRegex();
}
