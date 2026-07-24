namespace Randall.Contracts;

/// <summary>Lab target profile loaded from projects/*.yaml</summary>
public sealed class ProjectConfig
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>file | tcp | udp | http | https | harness — http/https use the TCP tube (+ TLS for https).</summary>
    public string Kind { get; set; } = "file";
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
    /// <summary>
    /// Oracle engine — judgment/reporting only (did the target behave wrongly?).
    /// See docs/ORACLES.md. Does not plan hunts or attribute AI vs human code.
    /// </summary>
    public OracleConfig? Oracles { get; set; }

    /// <summary>
    /// Bug Hunter engine — AI/human code analysis, mistake catalog, hunt planning,
    /// and campaign arming (suggests oracle rules / dictionaries). See docs/BUG_HUNTER.md.
    /// YAML: <c>bugHunter:</c> (preferred) or legacy <c>aiCode:</c>.
    /// </summary>
    public BugHunterConfig? BugHunter { get; set; }

    /// <summary>
    /// Magician engine — campaign adjustments when the Oracle reports needs.
    /// See docs/MAGICIAN.md. Does not judge runs or attribute AI vs human code.
    /// </summary>
    public MagicianConfig? Magician { get; set; }

    /// <summary>
    /// Joker engine — high-entropy / multi-mutator iterations. Magician can enable, sample,
    /// and follow up on Joker's crashes. See docs/MAGICIAN.md#joker.
    /// </summary>
    public JokerConfig? Joker { get; set; }

    /// <summary>Legacy YAML alias for <see cref="BugHunter"/> (<c>aiCode:</c>).</summary>
    public BugHunterConfig? AiCode
    {
        get => BugHunter;
        set
        {
            if (value is not null)
                BugHunter = value;
        }
    }

    /// <summary>Email / Discord alerts on unique crashes — see docs/NOTIFICATIONS.md.</summary>
    public NotificationsConfig? Notifications { get; set; }
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
    /// <summary>
    /// Optional <c>randall agent</c> base URL. When set, Target Runtime starts/stops/restarts
    /// the process on that host instead of locally (private LAN / localhost only).
    /// </summary>
    public string? AgentUrl { get; set; }
    /// <summary>Request Page Heap / stronger UAF signals when starting via Target Runtime (lab).</summary>
    public bool PageHeap { get; set; }
    /// <summary>
    /// Declarative post-start actions (wait-port, sleep, exec, tcp-send, …).
    /// Prefer these over brittle UI clicks; use <c>exec</c> for AutoIt/pywinauto when needed.
    /// </summary>
    public List<PostStartActionConfig> PostStart { get; set; } = [];

    /// <summary>
    /// In-process harness assembly or native DLL (when <c>fuzz.executionMode: in-process</c>
    /// or <c>kind: harness</c>). Managed: implements <c>IInProcessHarness</c>.
    /// Native: export <see cref="HarnessExport"/> (default LLVMFuzzerTestOneInput).
    /// </summary>
    public string? Harness { get; set; }
    /// <summary>auto | managed | native</summary>
    public string HarnessType { get; set; } = "auto";
    /// <summary>Native export name (C ABI: int fn(const uint8_t*, size_t)).</summary>
    public string HarnessExport { get; set; } = "LLVMFuzzerTestOneInput";
}

/// <summary>One Target Runtime post-start step. <see cref="Op"/> selects the action.</summary>
public sealed class PostStartActionConfig
{
    /// <summary>wait-port | sleep | exec | tcp-send | udp-send | http-get</summary>
    public string Op { get; set; } = "";
    public string? Host { get; set; }
    public int? Port { get; set; }
    public int? Ms { get; set; }
    public int? TimeoutMs { get; set; }
    public string? Command { get; set; }
    public List<string> Args { get; set; } = [];
    public string? WorkingDirectory { get; set; }
    public string? DataHex { get; set; }
    public string? DataText { get; set; }
    public string? Url { get; set; }
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
    /// <summary>
    /// Fuzz engine: <c>randall</c> (default generation + stalk), <c>aflpp</c> (AFL++ campaign),
    /// or <c>honggfuzz</c>. External engines are Linux file/harness campaigns — crashes and
    /// queue corpora sync back into Randfuzz. See docs/ENGINE_ADAPTERS.md.
    /// </summary>
    public string Engine { get; set; } = "randall";
    /// <summary>
    /// Wall-clock seconds for an external engine campaign (<c>afl-fuzz -V</c> / honggfuzz runtime).
    /// 0 = run until cancelled (Ctrl-C / session stop). Ignored when <see cref="Engine"/> is randall.
    /// </summary>
    public int EngineTimeoutSec { get; set; }
    /// <summary>
    /// Extra args inserted before <c>--</c> for AFL++ (e.g. <c>-Q</c> QEMU, <c>-c 0</c> CMPLOG).
    /// Space-separated. Ignored by the Randall engine.
    /// </summary>
    public string EngineExtraArgs { get; set; } = "";
    /// <summary>
    /// out-of-process (default) — spawn/file/TCP Target Runtime.
    /// in-process — feed bytes into a harness DLL (managed in-engine or native worker).
    /// </summary>
    public string ExecutionMode { get; set; } = "out-of-process";
    /// <summary>
    /// Persistent mode: keep harness/target warm across cases.
    /// null = default (true for in-process, false for out-of-process stdio).
    /// Explicit false = cold isolation (reload/respawn every iteration).
    /// </summary>
    public bool? Persistent { get; set; }
    /// <summary>
    /// Fork-server style warm worker + recycle after crash.
    /// null = default (follow Persistent for in-process).
    /// Explicit false with Persistent true = warm process but no crash-generation recycle labeling.
    /// Windows: warm worker (no Unix fork). See docs/HARNESS_DESIGN.md.
    /// </summary>
    public bool? ForkServer { get; set; }
    /// <summary>
    /// When true, refuse to start persistent in-process fuzzing if the harness
    /// does not implement <c>IInProcessHarnessReset</c> (honest state management).
    /// </summary>
    public bool HarnessStrict { get; set; }
    /// <summary>random (default) or exhaustive — walk commands × fields × mutators.</summary>
    public string Mode { get; set; } = "random";
    public int MaxIterations { get; set; } = 500;
    public string CorpusDir { get; set; } = "./data/corpus";
    public string CrashesDir { get; set; } = "./data/crashes";
    /// <summary>Default flow mutation: last | all | step indices.</summary>
    public string MutateStep { get; set; } = "last";
    /// <summary>When true and DynamoRIO is available, prioritize inputs that hit new edges.</summary>
    public bool CoverageGuided { get; set; }
    /// <summary>
    /// Extra console detail during fuzz (Oracle findings, Magician actions, Joker strategy,
    /// coverage edges, longer TX hex, INTEL on every crash including dedup).
    /// CLI: <c>randall fuzz -c … --verbose</c>.
    /// </summary>
    public bool Verbose { get; set; }
    /// <summary>
    /// When true (file/harness + DynamoRIO), also capture a <b>binary</b> drcov sidecar
    /// (no <c>-dump_text</c>) on novel coverage for optional Dragon Dance import.
    /// Text traces stay under <c>corpus/traces/</c>; binary under <c>corpus/traces-binary/</c>.
    /// See docs/GHIDRA_INTEGRATION.md.
    /// </summary>
    public bool CaptureBinaryDrcov { get; set; }
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
    /// <summary>
    /// After model patch, rewrite NetBIOS session (NBSS) 24-bit length to match the PDU.
    /// Needed for SMB-over-TCP labs so expand/insert on the body is actually delivered.
    /// Skipped when the mutated field is the NBSS length itself.
    /// </summary>
    public bool SyncNbssLength { get; set; }
    /// <summary>
    /// After model patch, rewrite HTTP Content-Length to match the body
    /// (web-app fuzzing). Prefer true for <c>kind: http|https</c> POST bodies.
    /// </summary>
    public bool SyncContentLength { get; set; }
    /// <summary>
    /// Absorb Set-Cookie from responses and inject Cookie on subsequent HTTP requests
    /// (minimal jar — see docs/WEB_FUZZ.md). Auto-on for kind http/https when unset? No — opt-in.
    /// </summary>
    public bool SyncCookies { get; set; }
    /// <summary>Write iterations.jsonl + run.json under runsDir (Phase 15).</summary>
    public bool ExecutionLog { get; set; } = true;
    /// <summary>Execution journal root (relative to project YAML).</summary>
    public string RunsDir { get; set; } = "../data/runs";
    /// <summary>auto | external | native | none — coverage trace backend (Phase 16).</summary>
    public string StalkMode { get; set; } = "auto";
    /// <summary>Write *_analysis.json from minidump when a crash is saved.</summary>
    public bool AutoAnalyzeCrash { get; set; } = true;
    /// <summary>
    /// Debugger integration: none | attach | wait.
    /// attach = launch WinDbg/Preview on the long-lived target PID (with g).
    /// wait = ProcDump/cdb headless dump-on-exception, then auto-analyze.
    /// </summary>
    public string DebuggerMode { get; set; } = "none";
    /// <summary>auto | windbg | windbg-preview | cdb</summary>
    public string DebuggerKind { get; set; } = "auto";
    /// <summary>After a crash dump is saved, open it in the GUI debugger.</summary>
    public bool DebuggerOpenOnCrash { get; set; }
    /// <summary>Start Sysinternals Procmon .pml capture for the duration of the fuzz run.</summary>
    public bool ProcmonCapture { get; set; }
    /// <summary>
    /// Sysinternals TCPVCon network connection snapshots at arm / disarm / crash
    /// (tcpvcon64.exe / tcpvcon.exe from the TCPView package).
    /// </summary>
    public bool TcpvconCapture { get; set; }
    /// <summary>
    /// Arm ProcDump -e -ma on the target PID when Scream wait is not already attached.
    /// </summary>
    public bool ProcdumpOnCrash { get; set; }
    /// <summary>Start Windows pktmon packet capture for the duration of the fuzz run.</summary>
    public bool PktmonCapture { get; set; }
    /// <summary>
    /// Start Wireshark tshark live capture → fuzz.pcapng for the duration of the fuzz run.
    /// Soft-fails if tshark/Npcap missing or capture denied (often needs elevation).
    /// </summary>
    public bool TsharkCapture { get; set; }
    /// <summary>
    /// Start Windows Performance Recorder (WPR) ETW capture for the run
    /// (light FileIO/Registry/DiskIO/Network → fuzz-etw.etl). Soft-fails if unavailable.
    /// </summary>
    public bool EtwCapture { get; set; }
    /// <summary>
    /// Start Sysinternals DebugView (Dbgview.exe) OutputDebugString capture for the run.
    /// </summary>
    public bool DebugViewCapture { get; set; }
    /// <summary>
    /// Sysinternals snapshot bundle: Handle + ListDLLs + PsList (+ AccessChk/VMMap/SigCheck when present)
    /// at arm/disarm/crash.
    /// </summary>
    public bool SysinternalsSnapshots { get; set; }
    /// <summary>
    /// Run Sysinternals Strings on the crashing input when a crash is saved
    /// (needs strings64.exe in tools/ or PATH).
    /// </summary>
    public bool StringsOnCrash { get; set; }
}
