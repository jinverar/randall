namespace Randall.Infrastructure;

/// <summary>
/// Progress/hub notifications must never abort an in-flight fuzz campaign
/// (recorder pipe-close and SignalR disconnect are benign mid-run noise).
/// </summary>
public static class FuzzProgressGuard
{
    public static void Try(IFuzzProgressSink? sink, Action<IFuzzProgressSink> notify)
    {
        if (sink is null)
            return;
        try
        {
            notify(sink);
        }
        catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
        {
            /* hub/recorder teardown — fuzz continues */
        }
    }
}
