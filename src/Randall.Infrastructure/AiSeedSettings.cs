namespace Randall.Infrastructure;

/// <summary>
/// Env-driven settings for the optional AI seed recipe feature.
/// Never required — Randfuzz fuzzes fine without an API key.
/// </summary>
public sealed record AiSeedSettings(
    string? ApiKey,
    string BaseUrl,
    string Model,
    int TimeoutSec)
{
    public const string EnvApiKey = "RANDALL_AI_API_KEY";
    public const string EnvApiKeyAlt = "OPENAI_API_KEY";
    public const string EnvBaseUrl = "RANDALL_AI_BASE_URL";
    public const string EnvModel = "RANDALL_AI_MODEL";
    public const string EnvTimeout = "RANDALL_AI_TIMEOUT_SEC";

    public bool HasApiKey => !string.IsNullOrWhiteSpace(ApiKey);

    public static AiSeedSettings FromEnvironment()
    {
        var key = Environment.GetEnvironmentVariable(EnvApiKey);
        if (string.IsNullOrWhiteSpace(key))
            key = Environment.GetEnvironmentVariable(EnvApiKeyAlt);

        var baseUrl = Environment.GetEnvironmentVariable(EnvBaseUrl);
        if (string.IsNullOrWhiteSpace(baseUrl))
            baseUrl = "https://api.openai.com/v1";

        var model = Environment.GetEnvironmentVariable(EnvModel);
        if (string.IsNullOrWhiteSpace(model))
            model = "gpt-4o-mini";

        var timeout = 60;
        var timeoutRaw = Environment.GetEnvironmentVariable(EnvTimeout);
        if (int.TryParse(timeoutRaw, out var t) && t > 0)
            timeout = Math.Clamp(t, 5, 600);

        return new AiSeedSettings(
            string.IsNullOrWhiteSpace(key) ? null : key.Trim(),
            baseUrl.Trim().TrimEnd('/'),
            model.Trim(),
            timeout);
    }
}
