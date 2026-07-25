using System.IO;
using Randall.Core;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public sealed class FuzzProgressGuardTests
{
    [Fact]
    public void Try_swallows_benign_hub_pipe_errors()
    {
        var sink = new ThrowingSink(new IOException("The pipe is being closed."));
        var ex = Record.Exception(() => FuzzProgressGuard.Try(sink, s => s.OnIteration(default!)));
        Assert.Null(ex);
    }

    [Fact]
    public void Try_rethrows_real_failures()
    {
        var sink = new ThrowingSink(new InvalidOperationException("Target Runtime start failed"));
        Assert.Throws<InvalidOperationException>(() =>
            FuzzProgressGuard.Try(sink, s => s.OnIteration(default!)));
    }

    private sealed class ThrowingSink(Exception toThrow) : IFuzzProgressSink
    {
        public void OnStarted(string project, string kind) => throw toThrow;
        public void OnIteration(FuzzIterationEvent iteration) => throw toThrow;
        public void OnCompleted(FuzzRunResult result) => throw toThrow;
        public void OnStopped(string reason) => throw toThrow;
        public void OnError(string message) => throw toThrow;
    }
}
