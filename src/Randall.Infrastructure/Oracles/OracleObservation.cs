using Randall.Contracts;

namespace Randall.Infrastructure.Oracles;

/// <summary>One post-execution observation fed into the oracle stack.</summary>
public sealed record OracleObservation(
    ProjectConfig Project,
    string YamlPath,
    byte[] Payload,
    TargetRunResult Result,
    string? CommandName,
    string? MutatorName,
    int Iteration,
    int NewEdges,
    int CoverageEdgeTotal,
    string? PluginAbortDetail,
    string? ExpectResponsePattern,
    OracleSessionTracker? Session = null);
