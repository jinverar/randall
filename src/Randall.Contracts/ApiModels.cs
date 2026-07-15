namespace Randall.Contracts;

public static class RandallLegs
{
    public const string Model = "model";
    public const string Mutate = "mutate";
    public const string Send = "send";
    public const string Stalk = "stalk";
    public const string Scream = "scream";
    public const string Proxy = "proxy";
    public const string Web = "web";
    public const string Pack = "pack";

    public static readonly IReadOnlyList<(string Id, string Title, string Summary)> All =
    [
        (Model, "Leg 1 — Model", "Block-based protocol definitions"),
        (Mutate, "Leg 2 — Mutate", "Field-aware mutation strategies"),
        (Send, "Leg 3 — Send", "TCP, UDP, file, and stdin transports"),
        (Stalk, "Leg 4 — Stalk", "DynamoRIO coverage and frontier detection"),
        (Scream, "Leg 5 — Scream", "Crash capture, dedup, and replay"),
        (Proxy, "Leg 6 — Proxy", "CANAPE-style MITM and live editing"),
        (Web, "Leg 7 — Web", "Browser UI and remote lab agent"),
        (Pack, "Leg 8 — Pack", "Standalone portable project bundles"),
    ];
}

public sealed record LegInfoDto(string Id, string Title, string Summary);

public sealed record HealthDto(string Name, string Version, string Status);

public sealed record CrashSummaryDto(Guid Id, string StackHash, string ExceptionCode, DateTimeOffset ObservedAt);
