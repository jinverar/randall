using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class LabCatalogTests
{
    [Fact]
    public void Library_IncludesNetworkAndDroneLabs()
    {
        var lib = LabServerManager.Library();
        Assert.Contains(lib.Labs, l => l.Id == "vulnserver" && l.Category == "network");
        Assert.Contains(lib.Labs, l => l.Id == "vulndrone-udp" && l.Category == "drone");
        Assert.Contains(lib.Labs, l => l.Id == "vulndrone-tcp" && l.Category == "drone");
        Assert.Contains(lib.Categories, c => c == "drone");
        Assert.Contains(lib.Categories, c => c == "network");
        Assert.Contains(LabCatalog.Categories(), c => c == "exploit-dev");
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
        Assert.Contains(DocsCatalog.Index, i => i.Path == "RPC_LAB.md");
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
}
