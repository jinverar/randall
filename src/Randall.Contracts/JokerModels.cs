namespace Randall.Contracts;

/// <summary>
/// Joker engine config — high-entropy / multi-mutator iterations.
/// Not Magician: Joker stacks mutators and optional wild bytes / bias flips;
/// Magician may enable, sample, and follow up on crashes. See docs/MAGICIAN.md#joker.
/// </summary>
public sealed class JokerConfig
{
    /// <summary>Master switch. Magician <c>summonJoker</c> can force-enable.</summary>
    public bool Enabled { get; set; }

    /// <summary>Base chance (0–1) that the Joker hijacks an iteration.</summary>
    public double Chance { get; set; } = 0.12;

    /// <summary>Max stacked mutators in one high-entropy iteration.</summary>
    public int MaxStack { get; set; } = 4;

    /// <summary>Inject random byte noise / length changes after the mutator stack.</summary>
    public bool WildBytes { get; set; } = true;

    /// <summary>Occasionally override session-flow / graph bias for one iteration.</summary>
    public bool FlipSessionBias { get; set; } = true;

    /// <summary>
    /// Magician encore — remaining iterations where Joker chance is boosted after enablement.
    /// Decremented by the Joker engine as it runs.
    /// </summary>
    public int EncoreIterations { get; set; }

    /// <summary>Chance while Magician encore is active (default 0.55).</summary>
    public double EncoreChance { get; set; } = 0.55;
}

/// <summary>One Joker high-entropy iteration (sampled when Magician watch is on).</summary>
public sealed record JokerActDto(
    string Id,
    string Project,
    string Trick,
    IReadOnlyList<string> MutatorChain,
    int ChaosLevel,
    string Detail,
    int Iteration,
    bool Crashed,
    bool Capitalized,
    DateTimeOffset At);
