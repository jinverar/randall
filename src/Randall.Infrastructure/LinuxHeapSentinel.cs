namespace Randall.Infrastructure;

/// <summary>
/// Arms glibc's built-in heap hardening for a target run so latent heap bugs (double-free, tcache
/// poisoning, overflow into chunk metadata) turn into an <em>immediate, labelled</em> abort instead
/// of silent corruption. This is the cheap, no-rebuild tier: glibc ≥ 2.26 ships tcache with a
/// double-free key and integrity checks; <c>glibc.malloc.check=3</c> + <c>MALLOC_PERTURB_</c> make
/// them fire eagerly and poison freed memory so use-after-free reads look wrong fast.
/// </summary>
public static class LinuxHeapSentinel
{
    public const string Summary =
        "glibc malloc hardening (glibc.malloc.check=3, MALLOC_PERTURB_) — latent heap bugs abort immediately with a labelled message";

    /// <summary>
    /// Environment variables to merge into a target process's environment. <paramref name="perturb"/>
    /// (1–255) is the MALLOC_PERTURB_ byte used to poison freed/allocated memory; a fixed value keeps
    /// crashes reproducible.
    /// </summary>
    public static IReadOnlyDictionary<string, string> HardeningEnv(int perturb = 165)
    {
        var b = ((perturb % 255) + 255) % 255;
        if (b == 0) b = 165;
        return new Dictionary<string, string>
        {
            // Newer glibc reads malloc.check via tunables; MALLOC_CHECK_ kept for older glibc.
            ["GLIBC_TUNABLES"] = "glibc.malloc.check=3",
            ["MALLOC_CHECK_"] = "3",
            ["MALLOC_PERTURB_"] = b.ToString(),
        };
    }

    /// <summary>Applies the hardening env onto a ProcessStartInfo-style environment dictionary.</summary>
    public static void Apply(IDictionary<string, string?> environment, int perturb = 165)
    {
        foreach (var kv in HardeningEnv(perturb))
            environment[kv.Key] = kv.Value;
    }
}
