using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Randall.Infrastructure;

/// <summary>
/// ECDSA P-256 (SHA-256) verification for update manifests.
/// Public key is embedded; override with env <c>RANDALL_UPDATE_PUBKEY_PEM</c> for lab/testing.
/// </summary>
public static class UpdateCrypto
{
    public const string PubKeyEnv = "RANDALL_UPDATE_PUBKEY_PEM";
    public const string SignKeyEnv = "RANDALL_UPDATE_SIGNING_KEY_PEM";

    /// <summary>Official Randfuzz update-manifest verify key (SPKI PEM).</summary>
    public const string EmbeddedPublicKeyPem =
        """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERDyt77nhPEfNBrDy09hknz6KfsmM
        6NAqHWLl5eHyOoPltoWk0i/HfAyffjK6TKz2LB4wfT8w0kgugi7wAKfaBw==
        -----END PUBLIC KEY-----
        """;

    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ResolvePublicKeyPem()
    {
        var env = Environment.GetEnvironmentVariable(PubKeyEnv);
        if (!string.IsNullOrWhiteSpace(env))
        {
            var t = env.Trim();
            if (t.Contains("BEGIN", StringComparison.Ordinal))
                return NormalizePem(t);
            // Allow base64 SPKI without PEM headers.
            return NormalizePem(
                "-----BEGIN PUBLIC KEY-----\n" + t + "\n-----END PUBLIC KEY-----");
        }

        return NormalizePem(EmbeddedPublicKeyPem);
    }

    public static bool VerifyManifest(string manifestJson, byte[] signature)
    {
        try
        {
            using var ecdsa = LoadPublicKey(ResolvePublicKeyPem());
            var data = Encoding.UTF8.GetBytes(NormalizeManifestBytes(manifestJson));
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
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

    public static string Sha256Hex(Stream stream)
    {
        stream.Position = 0;
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static bool FixedHexEquals(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
            return false;
        var aa = Convert.FromHexString(a.Trim());
        var bb = Convert.FromHexString(b.Trim());
        return CryptographicOperations.FixedTimeEquals(aa, bb);
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
    /// On 0.x, a minor bump with severity=major also counts (common pre-1.0 practice).
    /// </summary>
    public static bool IsMajorUpdate(string? current, string? latest, string? severity)
    {
        if (string.Equals(severity, "major", StringComparison.OrdinalIgnoreCase))
            return IsNewer(latest, current);

        var c = Parse(current);
        var l = Parse(latest);
        if (l.Major > c.Major)
            return true;
        return false;
    }

    [GeneratedRegex(@"^(\d+)\.(\d+)(?:\.(\d+))?$")]
    private static partial Regex SemVerRegex();
}
