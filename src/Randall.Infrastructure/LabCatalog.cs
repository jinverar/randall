using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Curated lab library — metadata for startable vuln servers and linked fuzz profiles.
/// Start/stop execution stays in <see cref="LabServerManager"/>.
/// </summary>
public static class LabCatalog
{
    internal sealed record Def(
        string Id,
        string Name,
        string Description,
        string Category,
        string Difficulty,
        int Port,
        string Protocol,
        string ProcessName,
        string ExeRelativePath,
        string ProjectYaml,
        string[] Tags,
        bool Startable = true,
        string? DocsPath = null,
        string? BuildHint = null,
        string[]? ExtraArgs = null);

    internal static readonly Def[] All =
    [
        // —— Network protocol labs ——
        new("vulnserver", "Vulnserver", "TCP multi-command session lab (TRUN/GMON/…)",
            "network", "intro", 9999, "tcp", "randall-vulnserver",
            "targets/vulnserver/randall-vulnserver.exe", "projects/vulnserver.yaml",
            ["tcp", "session-graph", "overflow"], DocsPath: "LAB_PRACTICE.md",
            BuildHint: "scripts/build-vulnserver.ps1 · scripts/build-lab-targets.sh"),
        new("vulnhttp", "VulnHttp", "HTTP/1.1 request-line / header parser lab",
            "network", "intro", 8080, "tcp", "randall-vulnhttp",
            "targets/vulnhttp/randall-vulnhttp.exe", "projects/vulnhttp.yaml",
            ["http", "parser", "headers"], DocsPath: "LAB_PRACTICE.md",
            BuildHint: "scripts/build-vulnhttp.ps1 · scripts/build-lab-targets.sh"),
        new("vulnftp", "VulnFtp", "FTP session / USER-PASS command lab",
            "network", "intro", 2121, "tcp", "randall-vulnftp",
            "targets/vulnftp/randall-vulnftp.exe", "projects/vulnftp.yaml",
            ["ftp", "session"], DocsPath: "LAB_PRACTICE.md",
            BuildHint: "scripts/build-vulnftp.ps1 · scripts/build-lab-targets.sh"),
        new("vulnssh", "VulnSsh", "SSH-shaped banner / version stub (not real crypto)",
            "network", "intro", 2222, "tcp", "randall-vulnssh",
            "targets/vulnssh/randall-vulnssh.exe", "projects/vulnssh.yaml",
            ["ssh-shaped", "banner"], DocsPath: "LAB_PRACTICE.md",
            BuildHint: "scripts/build-vulnssh.ps1 · scripts/build-lab-targets.sh"),
        new("vulntftp", "VulnTftp", "UDP TFTP RRQ/WRQ filename lab",
            "network", "intro", 6969, "udp", "randall-vulntftp",
            "targets/vulntftp/randall-vulntftp.exe", "projects/vulntftp.yaml",
            ["udp", "tftp", "filename"], DocsPath: "LAB_PRACTICE.md",
            BuildHint: "scripts/build-vulntftp.ps1 · scripts/build-lab-targets.sh"),
        new("vulnrpc", "VulnRpc", "DCE-shaped RPC bind / request lab",
            "network", "intermediate", 1355, "tcp", "randall-vulnrpc",
            "targets/vulnrpc/randall-vulnrpc.exe", "projects/vulnrpc.yaml",
            ["rpc", "dce-shaped"], DocsPath: "RPC_LAB.md",
            BuildHint: "scripts/build-vulnrpc.ps1 · scripts/build-lab-targets.sh"),
        new("vulnsmb", "VulnSmb", "NBSS+SMB2-shaped + pipe→DCE lab",
            "network", "intermediate", 4455, "tcp", "randall-vulnsmb",
            "targets/vulnsmb/randall-vulnsmb.exe", "projects/vulnsmb.yaml",
            ["smb-shaped", "nbss"], DocsPath: "SMB_LAB.md",
            BuildHint: "scripts/build-vulnsmb.ps1 · scripts/build-lab-targets.sh"),

        // —— Drone protocol / GCS-shaped labs (fictional RDL1 — not real MAVLink) ——
        new("vulndrone-udp", "VulnDrone UDP", "Fictional drone telemetry datagrams (RDL1) — length / msg-id crashes",
            "drone", "intermediate", 15550, "udp", "randall-vulndrone",
            "targets/vulndrone/randall-vulndrone.exe", "projects/vulndrone-udp.yaml",
            ["drone", "udp", "telemetry", "length-field"], DocsPath: "DRONE_LAB.md",
            BuildHint: "scripts/build-vulndrone.ps1 · scripts/build-lab-targets.sh",
            ExtraArgs: ["--mode", "udp"]),
        new("vulndrone-tcp", "VulnDrone TCP", "Fictional GCS command link (RDL1) — HELLO / CMD / MISSION frames",
            "drone", "intermediate", 15551, "tcp", "randall-vulndrone",
            "targets/vulndrone/randall-vulndrone.exe", "projects/vulndrone-tcp.yaml",
            ["drone", "tcp", "gcs-shaped", "mission"], DocsPath: "DRONE_LAB.md",
            BuildHint: "scripts/build-vulndrone.ps1 · scripts/build-lab-targets.sh",
            ExtraArgs: ["--mode", "tcp"]),

        // —— IoT / MQTT-shaped labs (fictional RMQ1 — not real MQTT wire) ——
        new("vulnmqtt", "VulnMqtt", "Fictional MQTT-shaped IoT broker (RMQ1) — CONNECT / PUBLISH / SUBSCRIBE length crashes",
            "iot", "intermediate", 18883, "tcp", "randall-vulnmqtt",
            "targets/vulnmqtt/randall-vulnmqtt.exe", "projects/vulnmqtt.yaml",
            ["mqtt-shaped", "iot", "tcp", "length-field"], DocsPath: "MQTT_LAB.md",
            BuildHint: "scripts/build-vulnmqtt.ps1 · scripts/build-lab-targets.sh"),

        // —— Exploit-dev / mitigation (native; start when built) ——
        // Port 9998 for UI start so it does not fight Vulnserver on 9999; fuzz YAML still defaults to 9999.
        new("vulnlab", "VulnLab (basic)", "Native mitigation-ladder TCP ECHO service (Linux/gcc). UI start uses :9998.",
            "exploit-dev", "advanced", 9998, "tcp", "vulnlab-basic",
            "targets/vulnlab/vulnlab-basic", "projects/vulnlab.yaml",
            ["native", "echo", "mitigation-ladder"], DocsPath: "MITIGATION_LAB.md",
            BuildHint: "scripts/build-mitigation-lab.sh"),

        // —— File parser labs (profile-only — fuzz via project YAML; no long-lived listener) ——
        new("file-text", "File Text", "Structured text/XML mini-parser — first-crash file fuzz path",
            "file", "intro", 0, "file", "",
            "targets/file-text/app.exe", "projects/file-text.yaml",
            ["file", "text", "xml", "mini-parser"], Startable: false,
            DocsPath: "TARGETS.md",
            BuildHint: "scripts/build-file-text.ps1 · scripts/build-file-text.sh"),
        new("file-framed", "File Framed", "Length-prefixed binary mini-parser — size / checksum bugs",
            "file", "intro", 0, "file", "",
            "targets/file-framed/app.exe", "projects/file-framed.yaml",
            ["file", "binary", "length-field", "mini-parser"], Startable: false,
            DocsPath: "TARGETS.md",
            BuildHint: "scripts/build-file-framed.ps1 · scripts/build-file-framed.sh"),
        new("reeldeck", "ReelDeck", "Media container (.rndl) player + studio paths — deeper file stalking",
            "file", "advanced", 0, "file", "",
            "targets/reeldeck/reeldeck", "projects/reeldeck.yaml",
            ["file", "media", "path-stalking", "deep-parser"], Startable: false,
            DocsPath: "REELDECK.md",
            BuildHint: "scripts/build-reeldeck.ps1 · scripts/build-reeldeck.sh"),
    ];

    public static IReadOnlyList<string> Categories() =>
        All.Select(d => d.Category).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c).ToList();

    internal static Def? Find(string id) =>
        All.FirstOrDefault(d => d.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    internal static IReadOnlyList<Def> Startable() =>
        All.Where(d => d.Startable).ToList();

    internal static LabLibraryEntryDto ToEntry(Def d) =>
        new(d.Id, d.Name, d.Description, d.Category, d.Difficulty, d.Port, d.Protocol,
            d.ProcessName, d.ExeRelativePath.Replace('\\', '/'), d.ProjectYaml.Replace('\\', '/'),
            d.Tags, d.Startable, d.DocsPath, d.BuildHint);
}
