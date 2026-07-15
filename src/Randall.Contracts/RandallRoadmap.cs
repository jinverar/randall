namespace Randall.Contracts;

public static class RandallRoadmap
{
    public static IReadOnlyList<RoadmapPhaseDto> Phases =>
    [
        new(1, "Lab targets + crash loop", "complete",
        [
            new("p1-yaml", "Project YAML loader", true, null),
            new("p1-mutators", "Tricky mutators", true, null),
            new("p1-vulnserver", "vulnserver TCP (TRUN)", true, null),
            new("p1-notepad", "Notepad++ file fuzz", true, null),
            new("p1-cfpass", "cfpass strange formats", true, null),
            new("p1-crashes", "Crash store + index.jsonl", true, null),
            new("p1-cli", "CLI targets/fuzz/crashes", true, null),
            new("p1-replay", "Full replay", true, null),
            new("p1-minidump", "Minidump on hang", true, null),
            new("p1-web", "Web crash browser", true, null),
        ]),
        new(2, "Stalk (DynamoRIO)", "active",
        [
            new("p2-drcov", "drcov wrapper", true, "scaffold — set DYNAMORIO_HOME"),
            new("p2-corpus", "Corpus priority by edges", true, "CorpusTracker scaffold"),
            new("p2-gui", "Coverage on file targets", false, null),
        ]),
        new(3, "Network + proxy", "planned",
        [
            new("p3-session", "Vulnserver session graph", false, null),
            new("p3-mitm", "CANAPE-style MITM", false, null),
        ]),
        new(4, "Crash stalking + Ghidra", "planned",
        [
            new("p4-dedup", "Path dedup + first diverge", false, null),
            new("p4-export", "drcov → Dragon Dance", false, null),
        ]),
        new(5, "Plugins + autopilot", "planned",
        [
            new("p5-rpp", "Python/Node/Rust plugins", false, null),
            new("p5-pack", "Standalone publish + scheduler", false, null),
        ]),
    ];
}
