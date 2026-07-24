namespace Randall.Infrastructure;

/// <summary>
/// Windows recorder teardown often closes stdout/stderr pipes while Randfuzz is still
/// draining them (tshark, wpr, pktmon, SignalR). These are not fuzz failures.
/// </summary>
public static class BenignRecorderPipeException
{
    public static bool IsBenign(Exception? ex)
    {
        while (ex is not null)
        {
            if (IsBenignMessage(ex.Message))
                return true;
            ex = ex.InnerException;
        }

        return false;
    }

    public static bool IsBenignMessage(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return false;

        return message.Contains("pipe is being closed", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("pipe is broken", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("broken pipe", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("I/O operation has been aborted", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("unable to write data to the transport connection", StringComparison.OrdinalIgnoreCase);
    }
}
