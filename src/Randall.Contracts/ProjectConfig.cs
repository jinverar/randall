namespace Randall.Contracts;

/// <summary>Lab target profile loaded from projects/*.yaml</summary>
public sealed class ProjectConfig
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Kind { get; set; } = "file"; // file | tcp
    public TargetConfig Target { get; set; } = new();
    public TransportConfig Transport { get; set; } = new();
    public FuzzConfig Fuzz { get; set; } = new();
    public List<string> Seeds { get; set; } = [];
    public List<string> Mutators { get; set; } = ["bitflip", "expand", "truncate"];
    /// <summary>TCP session commands (vulnserver TRUN, GMON, etc.) — random pick per iteration.</summary>
    public List<SessionCommandConfig> SessionCommands { get; set; } = [];
    /// <summary>RPP process plugins (Python/Node/Rust) — see docs/RPP.md.</summary>
    public List<PluginRefConfig> Plugins { get; set; } = [];
    /// <summary>Default block model for file targets (Leg 1).</summary>
    public string? Model { get; set; }
    /// <summary>Inline tokens for dictionary mutator — strings or hex:DEADBEEF.</summary>
    public List<string> Dictionary { get; set; } = [];
    /// <summary>Path to newline-delimited dictionary file (relative to project YAML).</summary>
    public string? DictionaryFile { get; set; }
    /// <summary>Stateful TCP sequences — probe then fuzz (e.g. STAT → TRUN).</summary>
    public List<SessionFlowConfig> SessionFlows { get; set; } = [];
    /// <summary>Response-driven graph (boofuzz s_switch) — branch on server replies.</summary>
    public SessionGraphConfig? SessionGraph { get; set; }
}

public sealed class SessionGraphConfig
{
    public string Start { get; set; } = "";
    /// <summary>Command to mutate during graph walk (default: last reachable step).</summary>
    public string Mutate { get; set; } = "";
    public List<SessionGraphEdgeConfig> Edges { get; set; } = [];
}

public sealed class SessionGraphEdgeConfig
{
    public string From { get; set; } = "";
    /// <summary>Substring match in server response (empty = any).</summary>
    public string When { get; set; } = "";
    public string To { get; set; } = "";
}

public sealed class SessionFlowConfig
{
    public string Name { get; set; } = "";
    public List<string> Steps { get; set; } = [];
    /// <summary>Which flow steps to mutate: last | all | comma indices e.g. "0,2".</summary>
    public string MutateStep { get; set; } = "";
}

public sealed class SessionCommandConfig
{
    public string Name { get; set; } = "";
    public string Prefix { get; set; } = "";
    public string? Seed { get; set; }
    /// <summary>Block model protocol (Leg 1) — replaces prefix+seed when set.</summary>
    public string? Model { get; set; }
    public bool ReadBanner { get; set; } = true;
    /// <summary>Optional fixed bytes sent before the mutated payload (e.g. STAT probe).</summary>
    public string? Preamble { get; set; }
    /// <summary>Substring expected in server response after this step (e.g. FTP 331).</summary>
    public string? ExpectResponse { get; set; }
}

public sealed class TargetConfig
{
    /// <summary>Path to target executable (vulnserver, local lab binary, etc.).</summary>
    public string Executable { get; set; } = "";
    public List<string> Args { get; set; } = [];
    public int TimeoutMs { get; set; } = 8000;
    /// <summary>For TCP targets: keep server process alive between iterations.</summary>
    public bool LongLived { get; set; }
    public string WorkingDirectory { get; set; } = "";
}

public sealed class TransportConfig
{
    public string Type { get; set; } = "file";
    public string Extension { get; set; } = ".bin";
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 9999;
    /// <summary>TCP: optional static prefix before mutated payload (e.g. TRUN /.:/)</summary>
    public string Prefix { get; set; } = "";
    public int ReceiveTimeoutMs { get; set; } = 2000;
    /// <summary>Wrap TCP in TLS (SslStream).</summary>
    public bool Tls { get; set; }
    /// <summary>Accept any server certificate — lab only.</summary>
    public bool TlsInsecure { get; set; } = true;
    /// <summary>SNI / TLS host override.</summary>
    public string? TlsHost { get; set; }
}

public sealed class FuzzConfig
{
    /// <summary>random (default) or exhaustive — walk commands × fields × mutators.</summary>
    public string Mode { get; set; } = "random";
    public int MaxIterations { get; set; } = 500;
    public string CorpusDir { get; set; } = "./data/corpus";
    public string CrashesDir { get; set; } = "./data/crashes";
    /// <summary>Default flow mutation: last | all | step indices.</summary>
    public string MutateStep { get; set; } = "last";
    /// <summary>When true and DynamoRIO is available, prioritize inputs that hit new edges.</summary>
    public bool CoverageGuided { get; set; }
    /// <summary>AFL-style energy: favor corpus entries that found new coverage.</summary>
    public bool PowerSchedule { get; set; } = true;
    /// <summary>Max stacked mutation rounds for havoc mutator.</summary>
    public int HavocDepth { get; set; } = 6;
    /// <summary>Probability [0-1] of using a session flow instead of random command.</summary>
    public double SessionFlowBias { get; set; } = 0.25;
    /// <summary>Probability [0-1] of using sessionGraph response branching.</summary>
    public double SessionGraphBias { get; set; } = 0.2;
    /// <summary>TCP + coverageGuided: spawn instrumented target per iteration (drcov).</summary>
    public bool CoverageTcpSpawn { get; set; } = true;
    /// <summary>Re-sync length fields after model patch (default: keep mutated length).</summary>
    public bool SyncLengthFields { get; set; }
    /// <summary>Write iterations.jsonl + run.json under runsDir (Phase 15).</summary>
    public bool ExecutionLog { get; set; } = true;
    /// <summary>Execution journal root (relative to project YAML).</summary>
    public string RunsDir { get; set; } = "../data/runs";
}
