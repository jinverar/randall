namespace Randall.Contracts;

public sealed record JokerTrickOutcome(
    int NewEdges,
    bool UniqueCrash,
    bool NewCoverage,
    int OracleScoreDelta,
    bool Crashed);

public sealed record JokerCardRecordDto(
    string Id,
    string TrickName,
    IReadOnlyList<string> Recipe,
    int ChaosLevel,
    bool WildBytes,
    bool FlipSessionBias,
    double Score,
    int NewEdges,
    int UniqueScreams,
    int ScareDoorHits,
    int OracleDelta,
    int ProductiveUses,
    bool Legendary,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastUsedAt);

public sealed record JokerDeckStateDto(
    int Version,
    DateTimeOffset UpdatedAt,
    IReadOnlyList<JokerCardRecordDto> Cards);

public sealed record JokerCardDrawDto(
    string PlayMode,
    JokerCardRecordDto? SourceCard,
    IReadOnlyList<string> Recipe,
    int ChaosLevel,
    bool WildBytes,
    bool FlipSessionBias,
    string Detail);
