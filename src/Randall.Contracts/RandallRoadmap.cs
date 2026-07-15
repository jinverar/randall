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
            new("p1-file-text", "File target — structured text/XML", true, null),
            new("p1-file-framed", "File target — length-prefixed binary", true, null),
            new("p1-crashes", "Crash store + index.jsonl", true, null),
            new("p1-cli", "CLI targets/fuzz/crashes", true, null),
            new("p1-replay", "Full replay", true, null),
            new("p1-minidump", "Minidump on hang", true, null),
            new("p1-web", "Web crash browser", true, null),
            new("p1-model", "Block protocol models (Leg 1)", true, "docs/MODEL.md"),
        ]),
        new(2, "Stalk (DynamoRIO)", "complete",
        [
            new("p2-drcov", "drcov wrapper", true, null),
            new("p2-corpus", "Corpus priority by edges", true, null),
            new("p2-web-fuzz", "Web UI fuzz control + SignalR", true, null),
            new("p2-gui", "Coverage on file targets", true, null),
        ]),
        new(3, "Network + proxy", "complete",
        [
            new("p3-session", "Vulnserver session graph", true, null),
            new("p3-mitm", "CANAPE-style MITM", true, null),
            new("p3-replay", "Live edit / replay in proxy", true, null),
        ]),
        new(4, "Crash stalking + Ghidra", "complete",
        [
            new("p4-dedup", "Path dedup + first diverge", true, null),
            new("p4-export", "Triage bundle export", true, null),
            new("p4-ghidra", "Ghidra / Dragon Dance artifacts", true, null),
        ]),
        new(5, "Plugins + autopilot", "complete",
        [
            new("p5-rpp", "RPP process plugins", true, null),
            new("p5-campaign", "Campaign scheduler", true, null),
            new("p5-pack", "Portable publish bundle", true, null),
            new("p5-bundle", "Project zip export", true, "randall bundle"),
        ]),
        new(6, "Intelligence + polish", "complete",
        [
            new("p6-field", "Field-aware model mutation", true, null),
            new("p6-size", "Size / length block primitive", true, "docs/MODEL.md"),
            new("p6-import", "bundle import command", true, "randall bundle import"),
            new("p6-dedup", "Crash hash dedup", true, null),
        ]),
        new(7, "Lab agent + mobility", "complete",
        [
            new("p7-agent", "randall agent — bind all interfaces", true, "randall agent"),
            new("p7-bundles-ui", "Web bundle export/import", true, null),
            new("p7-vuln-models", "Full vulnserver block models", true, null),
            new("p7-local", "Discover gitignored local projects", true, "projects/local/"),
            new("p7-autopilot", "Cursor Automations nightly template", true, "docs/AUTOPILOT.md"),
        ]),
        new(8, "Advanced techniques", "complete",
        [
            new("p8-havoc", "AFL-style stacked havoc mutator", true, "docs/FUZZING.md"),
            new("p8-interesting", "LibFuzzer interesting integers", true, null),
            new("p8-dictionary", "Dictionary / token injection", true, null),
            new("p8-splice", "Corpus crossover (splice)", true, null),
            new("p8-power", "Corpus energy power schedule", true, null),
            new("p8-flows", "Stateful TCP session flows", true, null),
            new("p8-clusters", "Crash clustering for triage", true, "/api/crashes/clusters"),
        ]),
        new(9, "Lab readiness", "complete",
        [
            new("p9-doctor", "randall doctor preflight checks", true, "randall doctor"),
            new("p9-udp", "UDP datagram transport", true, null),
            new("p9-crc", "CRC32 checksum block + resync", true, "docs/MODEL.md"),
            new("p9-havoc-model", "Field-level havoc in model fuzzer", true, null),
        ]),
    ];
}
