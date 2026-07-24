using Microsoft.AspNetCore.SignalR;
using Randall.Core;
using Randall.Infrastructure;

namespace Randall.Server;

public sealed class FuzzHub : Hub;

public sealed class SignalRFuzzProgressSink(IHubContext<FuzzHub> hub, FuzzLiveLogBuffer liveLog) : IFuzzProgressSink
{
    public void OnStarted(string project, string kind) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzStarted", new { project, kind }));

    public void OnTargetPid(int? pid) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzTargetPid", new { pid }));

    public void OnIteration(FuzzIterationEvent iteration) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzIteration", iteration));

    public void OnLog(FuzzLogEvent entry)
    {
        liveLog.Append(entry);
        SafeSend(() => hub.Clients.All.SendAsync("fuzzLog", entry));
    }

    public void OnCompleted(FuzzRunResult result) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzCompleted", new
        {
            result.Iterations,
            result.CorpusAdded,
            result.CrashesFound,
        }));

    public void OnStopped(string reason) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzStopped", new { reason }));

    public void OnError(string message) =>
        SafeSend(() => hub.Clients.All.SendAsync("fuzzError", new { message }));

    private static void SafeSend(Func<Task> send)
    {
        Task task;
        try
        {
            task = send();
        }
        catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
        {
            return;
        }

        _ = task.ContinueWith(
            t =>
            {
                if (t.IsFaulted && t.Exception is not null)
                {
                    foreach (var ex in t.Exception.InnerExceptions)
                    {
                        if (!BenignRecorderPipeException.IsBenign(ex))
                            Console.WriteLine($"SignalR notify failed: {ex.Message}");
                    }
                }
            },
            TaskContinuationOptions.OnlyOnFaulted);
    }
}
