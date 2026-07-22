using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Resolve notification config with env-var fallbacks for secrets.</summary>
public static class NotificationSettings
{
    public const string DiscordWebhookEnv = "RANDALL_DISCORD_WEBHOOK";
    public const string SmtpHostEnv = "RANDALL_SMTP_HOST";
    public const string SmtpUserEnv = "RANDALL_SMTP_USER";
    public const string SmtpPasswordEnv = "RANDALL_SMTP_PASSWORD";
    public const string SmtpFromEnv = "RANDALL_SMTP_FROM";
    public const string SmtpToEnv = "RANDALL_SMTP_TO";
    public const string UiBaseUrlEnv = "RANDALL_UI_BASE_URL";

    public static string? Env(string? name, string fallback)
    {
        var key = string.IsNullOrWhiteSpace(name) ? fallback : name.Trim();
        var value = Environment.GetEnvironmentVariable(key);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    public static string? ResolveDiscordWebhook(DiscordNotificationConfig? cfg)
    {
        if (cfg is null)
            return Env(null, DiscordWebhookEnv);
        if (!string.IsNullOrWhiteSpace(cfg.WebhookUrl))
            return cfg.WebhookUrl.Trim();
        return Env(cfg.WebhookUrlEnv, DiscordWebhookEnv);
    }

    public static string? ResolveUiBaseUrl(NotificationsConfig? cfg)
    {
        if (cfg is not null && !string.IsNullOrWhiteSpace(cfg.UiBaseUrl))
            return cfg.UiBaseUrl.Trim().TrimEnd('/');
        return Env(cfg?.UiBaseUrlEnv, UiBaseUrlEnv)?.TrimEnd('/');
    }

    public static ResolvedEmailSettings? ResolveEmail(EmailNotificationConfig? cfg)
    {
        if (cfg is null)
            return null;

        var host = FirstNonEmpty(cfg.SmtpHost, Env(cfg.SmtpHostEnv, SmtpHostEnv));
        var from = FirstNonEmpty(cfg.From, Env(cfg.FromEnv, SmtpFromEnv));
        var user = FirstNonEmpty(cfg.Username, Env(cfg.UsernameEnv, SmtpUserEnv));
        var pass = FirstNonEmpty(cfg.Password, Env(cfg.PasswordEnv, SmtpPasswordEnv));

        var to = new List<string>();
        foreach (var addr in cfg.To)
        {
            if (!string.IsNullOrWhiteSpace(addr))
                to.Add(addr.Trim());
        }

        var toEnv = Env(cfg.ToEnv, SmtpToEnv);
        if (!string.IsNullOrWhiteSpace(toEnv))
        {
            foreach (var part in toEnv.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!to.Contains(part, StringComparer.OrdinalIgnoreCase))
                    to.Add(part);
            }
        }

        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(from) || to.Count == 0)
            return null;

        return new ResolvedEmailSettings(
            host!,
            cfg.SmtpPort <= 0 ? 587 : cfg.SmtpPort,
            cfg.UseSsl,
            from!,
            to,
            user,
            pass);
    }

    public static bool AnyChannelConfigured(NotificationsConfig? cfg)
    {
        if (cfg is null || !cfg.Enabled)
            return false;
        var discordOk = cfg.Discord.Enabled && !string.IsNullOrWhiteSpace(ResolveDiscordWebhook(cfg.Discord));
        var emailOk = cfg.Email.Enabled && ResolveEmail(cfg.Email) is not null;
        return discordOk || emailOk;
    }

    public static string Describe(NotificationsConfig? cfg)
    {
        if (cfg is null)
            return "notifications not set";
        if (!cfg.Enabled)
            return "notifications.enabled: false";

        var parts = new List<string>();
        if (cfg.Discord.Enabled)
        {
            parts.Add(string.IsNullOrWhiteSpace(ResolveDiscordWebhook(cfg.Discord))
                ? "discord (missing webhook)"
                : "discord");
        }

        if (cfg.Email.Enabled)
        {
            parts.Add(ResolveEmail(cfg.Email) is null
                ? "email (incomplete SMTP)"
                : "email");
        }

        if (parts.Count == 0)
            return "enabled but no channels";
        return string.Join(", ", parts);
    }

    private static string? FirstNonEmpty(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) ? a.Trim() : (!string.IsNullOrWhiteSpace(b) ? b.Trim() : null);
}

public sealed record ResolvedEmailSettings(
    string SmtpHost,
    int SmtpPort,
    bool UseSsl,
    string From,
    IReadOnlyList<string> To,
    string? Username,
    string? Password);

/// <summary>Fan-out crash / campaign alerts to Discord + email.</summary>
public static class NotificationDispatcher
{
    private static readonly HttpClient Http = CreateHttp();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private static HttpClient CreateHttp()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Randfuzz", "1.0"));
        return client;
    }

    public static async Task<IReadOnlyList<NotificationSendResult>> NotifyCrashAsync(
        NotificationsConfig? config,
        CrashAlertDto alert,
        CancellationToken cancellationToken = default)
    {
        if (config is null || !config.Enabled || !config.OnUniqueCrash)
            return [];

        var results = new List<NotificationSendResult>();
        if (config.Discord.Enabled)
            results.Add(await SendDiscordCrashAsync(config.Discord, alert, cancellationToken));
        if (config.Email.Enabled)
            results.Add(await SendEmailCrashAsync(config.Email, alert, cancellationToken));
        return results;
    }

    public static async Task<IReadOnlyList<NotificationSendResult>> NotifyCampaignAsync(
        NotificationsConfig? config,
        CampaignAlertDto alert,
        CancellationToken cancellationToken = default)
    {
        if (config is null || !config.Enabled || !config.OnCampaignComplete)
            return [];

        var results = new List<NotificationSendResult>();
        if (config.Discord.Enabled)
            results.Add(await SendDiscordCampaignAsync(config.Discord, alert, cancellationToken));
        if (config.Email.Enabled)
            results.Add(await SendEmailCampaignAsync(config.Email, alert, cancellationToken));
        return results;
    }

    /// <summary>Send a one-shot test message on every configured channel.</summary>
    public static async Task<IReadOnlyList<NotificationSendResult>> SendTestAsync(
        NotificationsConfig config,
        CancellationToken cancellationToken = default)
    {
        var results = new List<NotificationSendResult>();
        var stamp = DateTimeOffset.UtcNow;
        var title = "Randfuzz notification test";
        var body = $"Test alert from Randfuzz at {stamp:u}. If you see this, Discord/email wiring works.";

        if (config.Discord.Enabled)
        {
            var url = NotificationSettings.ResolveDiscordWebhook(config.Discord);
            if (string.IsNullOrWhiteSpace(url))
                results.Add(new NotificationSendResult("discord", false, "Webhook URL not configured"));
            else
                results.Add(await PostDiscordAsync(url, config.Discord.Username, title, body, 0x57F287, cancellationToken));
        }

        if (config.Email.Enabled)
        {
            var email = NotificationSettings.ResolveEmail(config.Email);
            if (email is null)
                results.Add(new NotificationSendResult("email", false, "SMTP host/from/to incomplete"));
            else
                results.Add(await SendSmtpAsync(email, title, body, cancellationToken));
        }

        if (results.Count == 0)
            results.Add(new NotificationSendResult("none", false, "No channels enabled"));

        return results;
    }

    public static CrashAlertDto BuildCrashAlert(
        NotificationsConfig? config,
        SavedCrash saved,
        string? exceptionHint,
        string? detail)
    {
        var uiBase = NotificationSettings.ResolveUiBaseUrl(config);
        var uiUrl = uiBase is null ? null : $"{uiBase}/#crashes?id={saved.Id}";
        return new CrashAlertDto(
            saved.Project,
            saved.Id,
            saved.Iteration,
            saved.Mutator,
            saved.InputHash,
            exceptionHint,
            detail,
            saved.TriageTag,
            saved.InputPath,
            saved.MiniDumpPath,
            saved.SidecarPath,
            saved.RunId,
            uiUrl,
            saved.At);
    }

    public static CampaignAlertDto BuildCampaignAlert(
        NotificationsConfig? config,
        CampaignResultDto result)
    {
        var uiBase = NotificationSettings.ResolveUiBaseUrl(config);
        return new CampaignAlertDto(
            result.Name,
            result.Success,
            result.Runs.Count,
            result.Runs.Count(r => !r.Success),
            result.TotalCrashes,
            result.Runs,
            uiBase is null ? null : $"{uiBase}/#campaign",
            DateTimeOffset.UtcNow);
    }

    private static async Task<NotificationSendResult> SendDiscordCrashAsync(
        DiscordNotificationConfig cfg,
        CrashAlertDto alert,
        CancellationToken ct)
    {
        var url = NotificationSettings.ResolveDiscordWebhook(cfg);
        if (string.IsNullOrWhiteSpace(url))
            return new NotificationSendResult("discord", false, "Webhook URL not configured");

        var title = $"Unique crash — {alert.Project}";
        var sb = new StringBuilder();
        sb.AppendLine($"**Project:** `{alert.Project}`");
        sb.AppendLine($"**Crash:** `{alert.CrashId}`");
        sb.AppendLine($"**Iteration:** {alert.Iteration}");
        sb.AppendLine($"**Mutator:** `{alert.Mutator}`");
        if (!string.IsNullOrWhiteSpace(alert.ExceptionHint))
            sb.AppendLine($"**Exception:** {alert.ExceptionHint}");
        if (!string.IsNullOrWhiteSpace(alert.TriageTag))
            sb.AppendLine($"**Tag:** `{alert.TriageTag}`");
        if (!string.IsNullOrWhiteSpace(alert.Detail))
            sb.AppendLine($"**Detail:** {Truncate(alert.Detail, 400)}");
        if (!string.IsNullOrWhiteSpace(alert.InputPath))
            sb.AppendLine($"**Input:** `{alert.InputPath}`");
        if (!string.IsNullOrWhiteSpace(alert.MiniDumpPath))
            sb.AppendLine($"**Dump:** `{alert.MiniDumpPath}`");
        if (!string.IsNullOrWhiteSpace(alert.UiUrl))
            sb.AppendLine($"[Open in UI]({alert.UiUrl})");

        return await PostDiscordAsync(url, cfg.Username, title, sb.ToString(), 0xED4245, ct);
    }

    private static async Task<NotificationSendResult> SendDiscordCampaignAsync(
        DiscordNotificationConfig cfg,
        CampaignAlertDto alert,
        CancellationToken ct)
    {
        var url = NotificationSettings.ResolveDiscordWebhook(cfg);
        if (string.IsNullOrWhiteSpace(url))
            return new NotificationSendResult("discord", false, "Webhook URL not configured");

        var color = alert.Success ? 0x57F287 : 0xFEE75C;
        var title = $"Campaign complete — {alert.CampaignName}";
        var sb = new StringBuilder();
        sb.AppendLine($"**Success:** {(alert.Success ? "yes" : "no")}");
        sb.AppendLine($"**Runs:** {alert.TotalRuns} ({alert.FailedRuns} failed)");
        sb.AppendLine($"**Total crashes:** {alert.TotalCrashes}");
        foreach (var run in alert.Runs.Take(12))
        {
            var mark = run.Success ? "OK" : "FAIL";
            sb.AppendLine($"• **{mark}** `{run.Project}` — {run.Iterations} iter, {run.Crashes} crash(es)" +
                          (run.Error is null ? "" : $" — {Truncate(run.Error, 120)}"));
        }

        if (alert.Runs.Count > 12)
            sb.AppendLine($"… +{alert.Runs.Count - 12} more");
        if (!string.IsNullOrWhiteSpace(alert.UiUrl))
            sb.AppendLine($"[Campaign tab]({alert.UiUrl})");

        return await PostDiscordAsync(url, cfg.Username, title, sb.ToString(), color, ct);
    }

    private static async Task<NotificationSendResult> PostDiscordAsync(
        string webhookUrl,
        string? username,
        string title,
        string description,
        int color,
        CancellationToken ct)
    {
        try
        {
            var payload = new Dictionary<string, object?>
            {
                ["username"] = string.IsNullOrWhiteSpace(username) ? "Randfuzz" : username,
                ["embeds"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["title"] = title,
                        ["description"] = Truncate(description, 3900),
                        ["color"] = color,
                        ["timestamp"] = DateTimeOffset.UtcNow.ToString("o"),
                    },
                },
            };

            using var content = new StringContent(JsonSerializer.Serialize(payload, JsonOpts), Encoding.UTF8, "application/json");
            using var response = await Http.PostAsync(webhookUrl, content, ct);
            if (response.IsSuccessStatusCode)
                return new NotificationSendResult("discord", true, $"HTTP {(int)response.StatusCode}");

            var body = await response.Content.ReadAsStringAsync(ct);
            return new NotificationSendResult("discord", false,
                $"HTTP {(int)response.StatusCode}: {Truncate(body, 200)}");
        }
        catch (Exception ex)
        {
            return new NotificationSendResult("discord", false, ex.Message);
        }
    }

    private static async Task<NotificationSendResult> SendEmailCrashAsync(
        EmailNotificationConfig cfg,
        CrashAlertDto alert,
        CancellationToken ct)
    {
        var email = NotificationSettings.ResolveEmail(cfg);
        if (email is null)
            return new NotificationSendResult("email", false, "SMTP host/from/to incomplete");

        var subject = $"[Randfuzz] Unique crash — {alert.Project} ({alert.CrashId.ToString("N")[..8]})";
        var sb = new StringBuilder();
        sb.AppendLine($"Randfuzz unique crash alert");
        sb.AppendLine();
        sb.AppendLine($"Project:    {alert.Project}");
        sb.AppendLine($"Crash ID:   {alert.CrashId}");
        sb.AppendLine($"Iteration:  {alert.Iteration}");
        sb.AppendLine($"Mutator:    {alert.Mutator}");
        sb.AppendLine($"Hash:       {alert.InputHash}");
        if (!string.IsNullOrWhiteSpace(alert.ExceptionHint))
            sb.AppendLine($"Exception:  {alert.ExceptionHint}");
        if (!string.IsNullOrWhiteSpace(alert.TriageTag))
            sb.AppendLine($"Tag:        {alert.TriageTag}");
        if (!string.IsNullOrWhiteSpace(alert.Detail))
            sb.AppendLine($"Detail:     {alert.Detail}");
        if (!string.IsNullOrWhiteSpace(alert.InputPath))
            sb.AppendLine($"Input:      {alert.InputPath}");
        if (!string.IsNullOrWhiteSpace(alert.MiniDumpPath))
            sb.AppendLine($"Dump:       {alert.MiniDumpPath}");
        if (!string.IsNullOrWhiteSpace(alert.SidecarPath))
            sb.AppendLine($"Sidecar:    {alert.SidecarPath}");
        if (!string.IsNullOrWhiteSpace(alert.RunId))
            sb.AppendLine($"Run ID:     {alert.RunId}");
        if (!string.IsNullOrWhiteSpace(alert.UiUrl))
            sb.AppendLine($"UI:         {alert.UiUrl}");
        sb.AppendLine($"At (UTC):   {alert.At:u}");

        return await SendSmtpAsync(email, subject, sb.ToString(), ct);
    }

    private static async Task<NotificationSendResult> SendEmailCampaignAsync(
        EmailNotificationConfig cfg,
        CampaignAlertDto alert,
        CancellationToken ct)
    {
        var email = NotificationSettings.ResolveEmail(cfg);
        if (email is null)
            return new NotificationSendResult("email", false, "SMTP host/from/to incomplete");

        var subject = $"[Randfuzz] Campaign {(alert.Success ? "OK" : "partial")} — {alert.CampaignName} ({alert.TotalCrashes} crashes)";
        var sb = new StringBuilder();
        sb.AppendLine($"Randfuzz campaign complete");
        sb.AppendLine();
        sb.AppendLine($"Campaign:  {alert.CampaignName}");
        sb.AppendLine($"Success:   {alert.Success}");
        sb.AppendLine($"Runs:      {alert.TotalRuns} ({alert.FailedRuns} failed)");
        sb.AppendLine($"Crashes:   {alert.TotalCrashes}");
        sb.AppendLine();
        foreach (var run in alert.Runs)
        {
            sb.AppendLine($"  {(run.Success ? "OK" : "FAIL")} {run.Project}: {run.Iterations} iter, {run.Crashes} crashes" +
                          (run.Error is null ? "" : $" — {run.Error}"));
        }

        if (!string.IsNullOrWhiteSpace(alert.UiUrl))
        {
            sb.AppendLine();
            sb.AppendLine($"UI: {alert.UiUrl}");
        }

        sb.AppendLine($"At (UTC): {alert.At:u}");
        return await SendSmtpAsync(email, subject, sb.ToString(), ct);
    }

    private static Task<NotificationSendResult> SendSmtpAsync(
        ResolvedEmailSettings email,
        string subject,
        string body,
        CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using var message = new MailMessage
                {
                    From = new MailAddress(email.From),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = false,
                };
                foreach (var to in email.To)
                    message.To.Add(to);

#pragma warning disable SYSLIB0014 // SmtpClient is acceptable for lab SMTP alerts
                using var client = new SmtpClient(email.SmtpHost, email.SmtpPort)
                {
                    EnableSsl = email.UseSsl,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    Timeout = 20000,
                };
#pragma warning restore SYSLIB0014

                if (!string.IsNullOrWhiteSpace(email.Username))
                {
                    client.Credentials = new NetworkCredential(email.Username, email.Password ?? "");
                }
                else
                {
                    client.UseDefaultCredentials = false;
                }

                ct.ThrowIfCancellationRequested();
                client.Send(message);
                return new NotificationSendResult("email", true,
                    $"sent to {string.Join(", ", email.To)} via {email.SmtpHost}:{email.SmtpPort}");
            }
            catch (Exception ex)
            {
                return new NotificationSendResult("email", false, ex.Message);
            }
        }, ct);
    }

    private static string Truncate(string value, int max)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= max)
            return value;
        return value[..(max - 1)] + "…";
    }
}
