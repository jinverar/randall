namespace Randall.Infrastructure;

/// <summary>
/// Progressive instructor scaffolding levels 0–6 for Investigation panels.
/// Level 0 = full research (show all). Higher levels hide more teaching answers
/// so students work from crash + evidence atoms upward.
/// </summary>
public static class InstructorAssistance
{
    public const int MinLevel = 0;
    public const int MaxLevel = 6;

    /// <summary>Investigation panels that can be progressively hidden.</summary>
    public static class Panels
    {
        public const string RootCause = "RootCause";
        public const string Offset = "Offset";
        public const string PatternDepth = "PatternDepth";
        public const string Influence = "Influence";
        public const string Primitives = "Primitives";
        public const string ResearchPlan = "ResearchPlan";
        public const string Advisor = "Advisor";
    }

    /// <summary>Clamp to 0–6. Invalid / negative → 0.</summary>
    public static int Normalize(int level) =>
        level < MinLevel ? MinLevel : level > MaxLevel ? MaxLevel : level;

    /// <summary>
    /// Whether <paramref name="panel"/> should be hidden at the given assistance level.
    /// Unknown panel names are never hidden.
    /// </summary>
    public static bool ShouldHide(string panel, int level)
    {
        var lv = Normalize(level);
        if (lv <= 0 || string.IsNullOrWhiteSpace(panel))
            return false;

        // Cumulative hide matrix:
        // 1: RootCause, Offset
        // 2: + PatternDepth
        // 3: + Influence
        // 4: + Primitives
        // 5: + ResearchPlan (skeptic / plan)
        // 6: + Advisor
        return panel switch
        {
            Panels.RootCause or Panels.Offset => lv >= 1,
            Panels.PatternDepth => lv >= 2,
            Panels.Influence => lv >= 3,
            Panels.Primitives => lv >= 4,
            Panels.ResearchPlan => lv >= 5,
            Panels.Advisor => lv >= 6,
            _ => false,
        };
    }

    /// <summary>Backward-compat: instructor mode on ↔ level ≥ 1.</summary>
    public static bool ToInstructorMode(int level) => Normalize(level) >= 1;

    /// <summary>Map legacy bool onto levels (true → 1, false → 0).</summary>
    public static int FromInstructorMode(bool instructorMode) => instructorMode ? 1 : 0;
}
