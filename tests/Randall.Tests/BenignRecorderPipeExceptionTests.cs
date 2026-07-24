using System.IO;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public sealed class BenignRecorderPipeExceptionTests
{
    [Theory]
    [InlineData("The pipe is being closed.")]
    [InlineData("Pipe is broken.")]
    [InlineData("Unable to write data to the transport connection: The I/O operation has been aborted.")]
    public void IsBenignMessage_recognizes_recorder_and_hub_teardown_noise(string message)
    {
        Assert.True(BenignRecorderPipeException.IsBenignMessage(message));
        Assert.True(BenignRecorderPipeException.IsBenign(new IOException(message)));
    }

    [Theory]
    [InlineData("Target Runtime start failed")]
    [InlineData("Connection refused")]
    public void IsBenignMessage_rejects_real_failures(string message)
    {
        Assert.False(BenignRecorderPipeException.IsBenignMessage(message));
    }
}
