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
        Assert.Contains(lib.Categories, c => c == "robot");
        Assert.Contains(lib.Categories, c => c == "ai");
        Assert.Contains(LabCatalog.Categories(), c => c == "exploit-dev");
        Assert.Contains(lib.Labs, l => l.Id == "vulnmqtt" && l.Category == "iot");
        Assert.Contains(lib.Labs, l => l.Id == "vulnrobot" && l.Category == "robot");
        Assert.Contains(lib.Labs, l => l.Id == "vulnai" && l.Category == "ai");
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
        Assert.Contains(DocsCatalog.Index, i => i.Path == "ROBOT_LAB.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "AI_LAB.md");
        Assert.Contains(DocsCatalog.Index, i => i.Path == "RPC_LAB.md");
    }

    [Fact]
    public void RobotLabs_AreCataloguedUnderRobot()
    {
        var labs = LabServerManager.List(category: "robot");
        Assert.Contains(labs, l => l.Id == "vulnrobot");
        Assert.Contains(labs, l => l.Id == "vulnrobot-udp");
        Assert.Contains(labs, l => l.Id == "vulnrosbus");
        Assert.Contains(labs, l => l.Id == "vulnrobotio");

        var tcp = labs.First(l => l.Id == "vulnrobot");
        Assert.Equal(15560, tcp.Port);
        Assert.Equal("tcp", tcp.Protocol);
        Assert.True(tcp.Startable);
        Assert.Equal("ROBOT_LAB.md", tcp.DocsPath);
        Assert.Contains("robot", tcp.Tags!);

        var udp = labs.First(l => l.Id == "vulnrobot-udp");
        Assert.Equal(15561, udp.Port);
        Assert.Equal("udp", udp.Protocol);
        Assert.Equal(tcp.ProcessName, udp.ProcessName);

        var bus = labs.First(l => l.Id == "vulnrosbus");
        Assert.Equal(15562, bus.Port);
        Assert.Equal("tcp", bus.Protocol);

        var io = labs.First(l => l.Id == "vulnrobotio");
        Assert.Equal(15502, io.Port);
        Assert.Equal("tcp", io.Protocol);
        Assert.Contains("modbus-shaped", io.Tags!);

        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnrobot.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnrobot-udp.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnrosbus.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnrobotio.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnrobot_hello.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnrobot_udp.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnrosbus_topic.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnrobotio_read.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnRobot", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnRosBus", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnRobotIo", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "ROBOT_LAB.md")));
    }

    [Fact]
    public void AiLab_IsCataloguedUnderAi()
    {
        var labs = LabServerManager.List(category: "ai");
        Assert.Contains(labs, l => l.Id == "vulnai");
        var ai = labs.First(l => l.Id == "vulnai");
        Assert.Equal(18765, ai.Port);
        Assert.Equal("tcp", ai.Protocol);
        Assert.True(ai.Startable);
        Assert.Equal("AI_LAB.md", ai.DocsPath);
        Assert.Contains("bug-hunter", ai.Tags!);
        Assert.Contains("codegen", ai.Tags!);

        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        Assert.True(File.Exists(Path.Combine(root, "projects", "vulnai.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "projects", "protocols", "vulnai_infer.yaml")));
        Assert.True(File.Exists(Path.Combine(root, "targets", "Randall.VulnAi", "Program.cs")));
        Assert.True(File.Exists(Path.Combine(root, "examples", "vulnai-sample", "handler.c")));
        Assert.True(File.Exists(Path.Combine(root, "docs", "AI_LAB.md")));
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
