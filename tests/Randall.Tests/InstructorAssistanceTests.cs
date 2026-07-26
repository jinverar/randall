using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class InstructorAssistanceTests
{
    [Theory]
    [InlineData(-3, 0)]
    [InlineData(0, 0)]
    [InlineData(3, 3)]
    [InlineData(6, 6)]
    [InlineData(99, 6)]
    public void Normalize_clamps_to_0_through_6(int input, int expected) =>
        Assert.Equal(expected, InstructorAssistance.Normalize(input));

    [Theory]
    [InlineData(InstructorAssistance.Panels.RootCause, 0, false)]
    [InlineData(InstructorAssistance.Panels.RootCause, 1, true)]
    [InlineData(InstructorAssistance.Panels.Offset, 1, true)]
    [InlineData(InstructorAssistance.Panels.PatternDepth, 1, false)]
    [InlineData(InstructorAssistance.Panels.PatternDepth, 2, true)]
    [InlineData(InstructorAssistance.Panels.Influence, 2, false)]
    [InlineData(InstructorAssistance.Panels.Influence, 3, true)]
    [InlineData(InstructorAssistance.Panels.Primitives, 3, false)]
    [InlineData(InstructorAssistance.Panels.Primitives, 4, true)]
    [InlineData(InstructorAssistance.Panels.ResearchPlan, 4, false)]
    [InlineData(InstructorAssistance.Panels.ResearchPlan, 5, true)]
    [InlineData(InstructorAssistance.Panels.Advisor, 5, false)]
    [InlineData(InstructorAssistance.Panels.Advisor, 6, true)]
    public void ShouldHide_follows_progressive_matrix(string panel, int level, bool hidden) =>
        Assert.Equal(hidden, InstructorAssistance.ShouldHide(panel, level));

    [Fact]
    public void Level6_hides_all_scaffolded_panels()
    {
        foreach (var panel in new[]
                 {
                     InstructorAssistance.Panels.RootCause,
                     InstructorAssistance.Panels.Offset,
                     InstructorAssistance.Panels.PatternDepth,
                     InstructorAssistance.Panels.Influence,
                     InstructorAssistance.Panels.Primitives,
                     InstructorAssistance.Panels.ResearchPlan,
                     InstructorAssistance.Panels.Advisor,
                 })
        {
            Assert.True(InstructorAssistance.ShouldHide(panel, 6), panel);
        }
    }

    [Fact]
    public void Level0_shows_all_panels()
    {
        Assert.False(InstructorAssistance.ShouldHide(InstructorAssistance.Panels.RootCause, 0));
        Assert.False(InstructorAssistance.ShouldHide(InstructorAssistance.Panels.Advisor, 0));
    }

    [Fact]
    public void Unknown_panel_never_hidden() =>
        Assert.False(InstructorAssistance.ShouldHide("EvidenceAtoms", 6));

    [Fact]
    public void FromInstructorMode_maps_legacy_bool()
    {
        Assert.Equal(0, InstructorAssistance.FromInstructorMode(false));
        Assert.Equal(1, InstructorAssistance.FromInstructorMode(true));
        Assert.True(InstructorAssistance.ToInstructorMode(1));
        Assert.False(InstructorAssistance.ToInstructorMode(0));
    }
}
