using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class FuzzLiveLogBufferTests
{
    [Fact]
    public void Append_Snapshot_PreservesOrderForUiReplay()
    {
        var buf = new FuzzLiveLogBuffer();
        buf.Append(new FuzzLogEvent("info", "alpha", DateTimeOffset.UtcNow));
        buf.Append(new FuzzLogEvent("step", "bravo", DateTimeOffset.UtcNow, 1));
        var snap = buf.Snapshot();
        Assert.Equal(2, snap.Count);
        Assert.Equal("alpha", snap[0].Message);
        Assert.Equal("bravo", snap[1].Message);
    }

    [Fact]
    public void Clear_EmptiesBuffer_OnNewSession()
    {
        var buf = new FuzzLiveLogBuffer();
        buf.Append(new FuzzLogEvent("info", "stale", DateTimeOffset.UtcNow));
        buf.Clear();
        Assert.Empty(buf.Snapshot());
    }

    [Fact]
    public void FuzzSessionStatusDto_SerializesCamelCaseRunningPhase()
    {
        // UI poll reads s.running / s.phase — camelCase is required for Idle→Running sync.
        var dto = new FuzzSessionStatusDto(
            true, "running", "projects/vulnserver.yaml", 3, 1, 2, 0, true,
            "iter=3 havoc", 2192, "none", "vulnserver");
        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.GetProperty("running").GetBoolean());
        Assert.Equal("running", doc.RootElement.GetProperty("phase").GetString());
        Assert.Equal(2192, doc.RootElement.GetProperty("targetPid").GetInt32());
        Assert.Equal(3, doc.RootElement.GetProperty("iterations").GetInt32());
    }
}
