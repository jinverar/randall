namespace Randall.Contracts;

/// <summary>
/// Outbound alerts for unique crashes and campaign summaries.
/// Prefer env vars for secrets — see docs/NOTIFICATIONS.md.
/// </summary>
public sealed class NotificationsConfig
{
    /// <summary>Master switch. When false, no channels fire.</summary>
    public bool Enabled { get; set; }

    /// <summary>Notify when CrashStore saves a new unique crash (deduped by input hash).</summary>
    public bool OnUniqueCrash { get; set; } = true;

    /// <summary>Notify when a campaign finishes (campaign YAML).</summary>
    public bool OnCampaignComplete { get; set; }

    /// <summary>Optional deep-link base for crash UI (e.g. http://127.0.0.1:5000).</summary>
    public string? UiBaseUrl { get; set; }

    /// <summary>Env var name holding UiBaseUrl when not set inline (default RANDALL_UI_BASE_URL).</summary>
    public string? UiBaseUrlEnv { get; set; }

    public DiscordNotificationConfig Discord { get; set; } = new();
    public EmailNotificationConfig Email { get; set; } = new();
}

public sealed class DiscordNotificationConfig
{
    public bool Enabled { get; set; }

    /// <summary>Incoming webhook URL. Prefer <see cref="WebhookUrlEnv"/> for secrets.</summary>
    public string? WebhookUrl { get; set; }

    /// <summary>Env var for webhook URL (default RANDALL_DISCORD_WEBHOOK).</summary>
    public string? WebhookUrlEnv { get; set; }

    /// <summary>Override Discord username shown on the message.</summary>
    public string? Username { get; set; } = "Randfuzz";
}

public sealed class EmailNotificationConfig
{
    public bool Enabled { get; set; }

    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public bool UseSsl { get; set; } = true;

    public string? From { get; set; }
    public List<string> To { get; set; } = [];

    /// <summary>SMTP username (prefer UsernameEnv).</summary>
    public string? Username { get; set; }

    /// <summary>SMTP password (prefer PasswordEnv).</summary>
    public string? Password { get; set; }

    public string? SmtpHostEnv { get; set; }
    public string? UsernameEnv { get; set; }
    public string? PasswordEnv { get; set; }
    public string? FromEnv { get; set; }
    public string? ToEnv { get; set; }
}

/// <summary>Payload for a unique crash alert.</summary>
public sealed record CrashAlertDto(
    string Project,
    Guid CrashId,
    int Iteration,
    string Mutator,
    string InputHash,
    string? ExceptionHint,
    string? Detail,
    string? TriageTag,
    string? InputPath,
    string? MiniDumpPath,
    string? SidecarPath,
    string? RunId,
    string? UiUrl,
    DateTimeOffset At);

/// <summary>Payload for a campaign completion alert.</summary>
public sealed record CampaignAlertDto(
    string CampaignName,
    bool Success,
    int TotalRuns,
    int FailedRuns,
    int TotalCrashes,
    IReadOnlyList<CampaignRunResult> Runs,
    string? UiUrl,
    DateTimeOffset At);

/// <summary>Result of sending one channel notification.</summary>
public sealed record NotificationSendResult(
    string Channel,
    bool Ok,
    string Message);
