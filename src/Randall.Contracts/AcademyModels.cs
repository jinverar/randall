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

    /// <summary>Hide root-cause, offset, and primitive panels for guided instruction.</summary>
    public bool InstructorMode { get; set; }

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
