namespace Randall.Contracts;

/// <summary>
/// Academy / instructor presentation settings — Learning vs Research modes and silent oracle screams.
/// YAML: <c>academy:</c> on project profiles. UI prefs can override presentation for the console.
/// </summary>
public sealed class AcademyConfig
{
    /// <summary>
    /// <c>learning</c> — educational blurbs on influence/root-cause panels.
    /// <c>research</c> — denser evidence tables (default).
    /// </summary>
    public string PresentationMode { get; set; } = "research";

    /// <summary>
    /// Legacy flag: hide early Investigation answers for guided instruction.
    /// Kept for YAML / API backward compat — equivalent to <see cref="InstructorLevel"/> ≥ 1.
    /// </summary>
    public bool InstructorMode
    {
        get => InstructorLevel >= 1;
        set
        {
            if (value && InstructorLevel < 1)
                InstructorLevel = 1;
            else if (!value)
                InstructorLevel = 0;
        }
    }

    /// <summary>
    /// Progressive instructor scaffolding 0–6 (0 = off / full research; 6 = max hide).
    /// Higher levels hide more Investigation panels so students work upward from evidence atoms.
    /// </summary>
    public int InstructorLevel { get; set; }

    /// <summary>
    /// Promote high oracle invariant violations into scream-like canisters (no memory crash required).
    /// Feeds RootCause / Influence / Evidence pipeline.
    /// </summary>
    public bool SilentScreams { get; set; } = true;

    public bool IsLearningMode =>
        PresentationMode.Equals("learning", StringComparison.OrdinalIgnoreCase);

    public bool IsResearchMode =>
        !IsLearningMode;
}
