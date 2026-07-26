using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ResearchPlannerSkepticTests
{
    [Fact]
    public void Planner_orders_claims_into_experiment_steps()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "lab", null, null, obs, null, null, null, null, null);
        var primitives = PrimitiveEngine.Build(id, "lab", influence, root, obs);
        var plan = ResearchPlannerEngine.Build(id, "lab", root, influence, primitives);

        Assert.True(plan.Ok);
        Assert.NotEmpty(plan.Claims);
        Assert.NotEmpty(plan.Steps);
        Assert.Contains(plan.Steps, s => s.Experiment.Kind != 0 || s.Order >= 1);
        Assert.DoesNotContain(plan.Summary ?? "", "shellcode", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(plan.Objective, "ROP", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Skeptic_proposes_falsification_and_apply_observation_updates_confidence()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 41414141\n",
            regs: "rax=0000000041414141\n");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "lab", null, null, obs, null, null, null, null, null);
        var primitives = PrimitiveEngine.Build(id, "lab", influence, root, obs);
        var plan = ResearchPlannerEngine.Build(id, "lab", root, influence, primitives);
        var skeptic = SkepticEngine.Build(id, "lab", plan, root, influence, primitives);

        Assert.True(skeptic.Ok);
        Assert.NotEmpty(skeptic.Challenges);
        Assert.All(skeptic.Challenges, c => Assert.Equal(SkepticChallengeStatus.Proposed, c.Status));

        var first = skeptic.Challenges[0];
        var updated = SkepticEngine.ApplyObservation(
            skeptic, first.Id, SkepticChallengeStatus.Survived, "fault class unchanged after neutralize");
        var settled = updated.Challenges.First(c => c.Id == first.Id);
        Assert.Equal(SkepticChallengeStatus.Survived, settled.Status);
        Assert.True(settled.ClaimConfidenceAfter > settled.ClaimConfidenceBefore);
    }

    [Fact]
    public void Persist_round_trips_plan_and_skeptic()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-plan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n");
            var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
            var plan = ResearchPlannerEngine.PersistForCrash(dir, id, "lab", root);
            var skeptic = SkepticEngine.PersistForCrash(dir, id, "lab", plan, root);

            Assert.NotNull(ResearchPlannerEngine.TryReadForCrash(dir, id));
            Assert.NotNull(SkepticEngine.TryReadForCrash(dir, id));
            Assert.Equal(plan.Objective, ResearchPlannerEngine.TryReadForCrash(dir, id)!.Objective);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
