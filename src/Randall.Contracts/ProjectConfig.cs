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
}

public sealed class TargetConfig
{
    /// <summary>Path to vulnserver.exe, notepad++.exe, cfpass.exe, etc.</summary>
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
}
