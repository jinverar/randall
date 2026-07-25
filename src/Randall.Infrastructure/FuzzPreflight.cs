using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Lightweight checks before arming recorders or starting the target runtime.</summary>
public static class FuzzPreflight
{
    /// <summary>
    /// Returns an error message when the configured target binary is missing and fuzz would need it.
    /// </summary>
    public static string? ValidateTargetExecutable(ProjectConfig project, string yamlPath, bool dryRun)
    {
        if (dryRun)
            return null;

        if (InProcessSession.IsInProcess(project))
            return null;

        var exe = project.Target.Executable;
        if (string.IsNullOrWhiteSpace(exe))
            return null;

        var declared = ProjectLoader.ResolvePath(yamlPath, exe);
        if (ExecutableResolver.FindExisting(declared) is not null)
            return null;

        // TCP/UDP without longLived may hit an already-listening service (no local binary).
        if ((ProjectKinds.IsTcpLike(project) || ProjectKinds.IsUdp(project))
            && !project.Target.LongLived
            && !(project.Fuzz.Persistent ?? false)
            && !(project.Fuzz.ForkServer ?? false))
            return null;

        var hint = LabDoctor.SuggestBuildHint(project, yamlPath);
        return $"Target executable not found: {declared}. Build it first — {hint}";
    }
}
