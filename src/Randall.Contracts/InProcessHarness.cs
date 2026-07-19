namespace Randall.Contracts;

/// <summary>
/// Managed in-process harness. Design principles: <c>docs/HARNESS_DESIGN.md</c>.
/// <para><b>One rule:</b> let the target reject invalid input — do not filter in the harness.</para>
/// </summary>
public interface IInProcessHarness
{
    /// <summary>
    /// Feed one test case into the target.
    /// <list type="bullet">
    /// <item><description><b>0</b> — normal completion, including “target rejected / errored”.</description></item>
    /// <item><description><b>non-zero</b> — explicit abort signal (prefer throwing for real faults).</description></item>
    /// <item><description><b>throw</b> — crash transparency: recorded as a crash.</description></item>
    /// </list>
    /// Do not drop or sanitize <paramref name="data"/> before the target sees it
    /// (controlled mapping only — see harness design principles).
    /// </summary>
    int FuzzOne(ReadOnlySpan<byte> data);
}

/// <summary>
/// Session lifecycle — <b>session state</b> only (created once, destroyed once).
/// Per-case state belongs in <see cref="IInProcessHarnessReset"/>.
/// </summary>
public interface IInProcessHarnessLifecycle : IInProcessHarness
{
    /// <summary>Once when the harness loads — load libraries, read config, alloc reusable scratch.</summary>
    void Initialize();

    /// <summary>Once when the fuzz session ends — release session resources.</summary>
    void Shutdown();
}

/// <summary>
/// Per-iteration reset for persistent / forkServer mode.
/// Must clear <b>iteration state</b> so the next <see cref="IInProcessHarness.FuzzOne"/>
/// cannot observe the previous case (no persistent side effects).
/// Required for honest persistent fuzzing — Randfuzz warns if missing,
/// or refuses to start when <c>fuzz.harnessStrict: true</c>.
/// </summary>
public interface IInProcessHarnessReset : IInProcessHarness
{
    /// <summary>
    /// Called before every <see cref="IInProcessHarness.FuzzOne"/> while the process stays warm.
    /// Restore the target-facing state to pristine; do not rely on “first call” flags.
    /// </summary>
    void Reset();
}
