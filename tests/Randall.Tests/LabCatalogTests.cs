using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class LabCatalogTests
{
    [Fact]
    public void Library_IncludesNetworkDroneAndFileLabs()
    {
        var lib = LabServerManager.Library();
        Assert.Contains(lib.Labs, l => l.Id == "vulnserver" && l.Category == "network");
        Assert.Contains(lib.Labs, l => l.Id == "vulndrone-udp" && l.Category == "drone");
        Assert.Contains(lib.Labs, l => l.Id == "vulndrone-tcp" && l.Category == "drone");
        Assert.Contains(lib.Labs, l => l.Id == "file-text" && l.Category == "file" && !l.Startable);
        Assert.Contains(lib.Labs, l => l.Id == "file-framed" && l.Category == "file" && !l.Startable);
        Assert.Contains(lib.Labs, l => l.Id == "reeldeck" && l.Category == "file" && !l.Startable);
        Assert.Contains(lib.Categories, c => c == "drone");
        Assert.Contains(lib.Categories, c => c == "network");
        Assert.Contains(lib.Categories, c => c == "file");
        Assert.Contains(lib.Categories, c => c == "iot");
        Assert.Contains(LabCatalog.Categories(), c => c == "exploit-dev");
        Assert.Contains(lib.Labs, l => l.Id == "vulnmqtt" && l.Category == "iot");
    }

    [Fact]
    public void FileLabs_AreProfileOnly_AndRefuseStart()
    {
        var files = LabServerManager.List(category: "file");
        Assert.Equal(3, files.Count);
        Assert.All(files, l =>
        {
            Assert.Equal("file", l.Category);
            Assert.False(l.Startable);
            Assert.Equal("file", l.Protocol);
            Assert.Equal(0, l.Port);
            Assert.False(l.Running);
            Assert.Equal("profile", l.BindHint);
        });

        var start = LabServerManager.Start("file-text");
        Assert.False(start.Ok);
        Assert.Contains("profile-only", start.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DroneLabs_ShareBinary_WithDistinctPorts()
    {
        var labs = LabServerManager.List(category: "drone");
        var udp = labs.First(l => l.Id == "vulndrone-udp");
        var tcp = labs.First(l => l.Id == "vulndrone-tcp");
        Assert.Equal(udp.ProcessName, tcp.ProcessName);
        Assert.Equal(15550, udp.Port);
        Assert.Equal(15551, tcp.Port);
        Assert.Equal("udp", udp.Protocol);
        Assert.Equal("tcp", tcp.Protocol);
        Assert.Equal("DRONE_LAB.md", udp.DocsPath);
        Assert.Contains("vulndrone", udp.ExeRelativePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Library_FiltersByCategory()
    {
        var drone = LabServerManager.Library(category: "drone");
        Assert.All(drone.Labs, l => Assert.Equal("drone", l.Category));
        Assert.Contains(drone.Labs, l => l.Id == "vulndrone-udp");
        Assert.Contains(drone.Categories, c => c == "drone");

        var all = LabServerManager.List();
        Assert.True(all.Count >= drone.Labs.Count);
    }

    [Fact]
    public void DocsCatalog_IncludesLabLibraryAndDrone()
    {
        Assert.Contains(DocsCatalog.Index, i => i.Path == "LAB_LIBRARY.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "DRONE_LAB.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "MQTT_LAB.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "RPC_LAB.md");
    }

    [Fact]
    public void MqttLab_IsCataloguedUnderIot()
    {
        var labs = LabServerManager.List(category: "iot");
        Assert.Contains(labs, l => l.Id == "vulnmqtt");
        var mqtt = labs.First(l => l.Id == "vulnmqtt");
        Assert.Equal(18883, mqtt.Port);
        Assert.Equal("tcp", mqtt.Protocol);
        Assert.True(mqtt.Startable);
        Assert.Equal("MQTT_LAB.md", mqtt.DocsPath);
        Assert.Contains("mqtt-shaped", mqtt.Tags!);

        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnmqtt.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnmqtt_connect.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnMqtt", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "MQTT_LAB.md")));
    }

    [Fact]
    public void DroneProjectFiles_Exist()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulndrone-udp.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulndrone-tcp.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulndrone_udp.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnDrone", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "DRONE_LAB.md")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "LAB_LIBRARY.md")));
    }

    [Fact]
    public void FileProjectFiles_Exist()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "projects", "file-text.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "file-framed.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "reeldeck.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "REELDECK.md")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "TARGETS.md")));
    }
}
