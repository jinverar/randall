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
}

public sealed class SessionFlowConfig
{
    public string Name { get; set; } = "";
    public List<string> Steps { get; set; } = [];
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
}

public sealed class FuzzConfig
{
    public int MaxIterations { get; set; } = 500;
    public string CorpusDir { get; set; } = "./data/corpus";
    public string CrashesDir { get; set; } = "./data/crashes";
    /// <summary>When true and DynamoRIO is available, prioritize inputs that hit new edges.</summary>
    public bool CoverageGuided { get; set; }
    /// <summary>AFL-style energy: favor corpus entries that found new coverage.</summary>
    public bool PowerSchedule { get; set; } = true;
    /// <summary>Max stacked mutation rounds for havoc mutator.</summary>
    public int HavocDepth { get; set; } = 6;
    /// <summary>Probability [0-1] of using a session flow instead of random command.</summary>
    public double SessionFlowBias { get; set; } = 0.25;
    /// <summary>Re-sync length fields after model patch (default: keep mutated length).</summary>
    public bool SyncLengthFields { get; set; }
}
