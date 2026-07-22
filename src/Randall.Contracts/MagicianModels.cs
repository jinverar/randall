namespace Randall.Contracts;

/// <summary>
/// Magician engine config — intervention layer between Oracle needs and live campaign actions.
/// Casts "spells" on the target under test and can summon helpers (hunter / knight / army / bots).
/// See docs/MAGICIAN.md. Does not judge runs (Oracle) or attribute AI code (Bug Hunter).
/// </summary>
public sealed class MagicianConfig
{
    /// <summary>Master switch. When false, Magician is skipped.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>React to Oracle findings / needs during fuzz.</summary>
    public bool AutoCastOnOracle { get; set; } = true;

    /// <summary>Bless the campaign once at fuzz start (army mutators + hunter arming hints).</summary>
    public bool BlessOnStart { get; set; } = true;

    /// <summary>Write spells.jsonl under crashes/_magician/.</summary>
    public bool PersistSpells { get; set; } = true;

    /// <summary>Max spell casts per Oracle evaluation (deduped by spell id).</summary>
    public int MaxSpellsPerEval { get; set; } = 4;

    /// <summary>
    /// Allowed spell ids (empty = all). Examples: dictionaryBoost, havocSurge, energyBless,
    /// rearmOracles, summonHunter, summonKnight, summonArmy, summonBots.
    /// </summary>
    public List<string> AllowedSpells { get; set; } = [];

    /// <summary>When Oracle asks for bots, write an analyst hint for AI seed / hunt (no live API call).</summary>
    public bool AllowSummonBots { get; set; } = true;

    /// <summary>When Oracle asks for a knight, enable coverageGuided if off.</summary>
    public bool AllowSummonKnight { get; set; } = true;

    /// <summary>When Oracle asks for an army, ensure a broad mutator set.</summary>
    public bool AllowSummonArmy { get; set; } = true;

    /// <summary>When Oracle asks for hunter help, re-run Bug Hunter arming.</summary>
    public bool AllowSummonHunter { get; set; } = true;

    /// <summary>Magician may call on the Joker (chaotic random fuzz tricks).</summary>
    public bool AllowSummonJoker { get; set; } = true;

    /// <summary>Log / watch Joker tricks during fuzz (even when they miss).</summary>
    public bool WatchJoker { get; set; } = true;

    /// <summary>When the Joker finds a crash, Magician capitalizes (energy, army, corpus).</summary>
    public bool CapitalizeJokerCrashes { get; set; } = true;
}

/// <summary>
/// What the Oracle asks the Magician for — foresight / monitoring signal, not a judgment itself.
/// </summary>
public sealed record OracleNeedDto(
    /// <summary>dictionary | energy | hunter | knight | army | bots | rearm</summary>
    string Request,
    string Reason,
    string? RuleClass,
    string? RuleId,
    string Severity);

/// <summary>One cast spell (intervention) recorded by the Magician.</summary>
public sealed record MagicianSpellDto(
    string Id,
    string Project,
    string Spell,
    string? Summon,
    string Reason,
    string? RuleClass,
    string? RuleId,
    int Iteration,
    string Detail,
    DateTimeOffset At);

/// <summary>Result of Magician casting for one Oracle evaluation or manual cast.</summary>
public sealed record MagicianCastResult(
    IReadOnlyList<MagicianSpellDto> Spells,
    IReadOnlyList<string> MutatorsEnsured,
    IReadOnlyList<string> DictionaryTokensAdded,
    int ExtraEnergyBoost,
    bool CoverageGuidedEnabled,
    bool HunterRearmed,
    string Summary);
