using Microsoft.AspNetCore.SignalR;
using Randall.Core;
using Randall.Infrastructure;

namespace Randall.Server;

public sealed class FuzzHub : Hub;

public sealed class SignalRFuzzProgressSink(IHubContext<FuzzHub> hub, FuzzLiveLogBuffer liveLog) : IFuzzProgressSink
{
    public void OnStarted(string project, string kind) =>
        _ = hub.Clients.All.SendAsync("fuzzStarted", new { project, kind });

    public void OnTargetPid(int? pid) =>
        _ = hub.Clients.All.SendAsync("fuzzTargetPid", new { pid });

    public void OnIteration(FuzzIterationEvent iteration) =>
        _ = hub.Clients.All.SendAsync("fuzzIteration", iteration);

    public void OnLog(FuzzLogEvent entry)
    {
        liveLog.Append(entry);
        _ = hub.Clients.All.SendAsync("fuzzLog", entry);
    }

    public void OnCompleted(FuzzRunResult result) =>
        _ = hub.Clients.All.SendAsync("fuzzCompleted", new
        {
            result.Iterations,
            result.CorpusAdded,
            result.CrashesFound,
        });

    public void OnStopped(string reason) =>
        _ = hub.Clients.All.SendAsync("fuzzStopped", new { reason });

    public void OnError(string message) =>
        _ = hub.Clients.All.SendAsync("fuzzError", new { message });
}
