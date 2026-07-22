using System.Text;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class NbssFramingTests
{
    [Fact]
    public void TrySyncLength_RewritesMismatch_LeavesTypeNonZero()
    {
        var bad = new byte[] { 0x00, 0x00, 0x00, 0x01, 0x41, 0x42, 0x43, 0x44 }; // claims 1, has 4
        var synced = NbssFraming.TrySyncLength(bad);
        Assert.Equal(4, (synced[1] << 16) | (synced[2] << 8) | synced[3]);
        Assert.Equal(0x41, synced[4]);

        var keep = new byte[] { 0x81, 0x00, 0x00, 0x00 }; // non-session type
        Assert.Same(keep, NbssFraming.TrySyncLength(keep));
    }

    [Fact]
    public void TrySyncLength_IdempotentWhenCorrect()
    {
        var ok = new byte[] { 0x00, 0x00, 0x00, 0x02, 0x41, 0x42 };
        Assert.Same(ok, NbssFraming.TrySyncLength(ok));
    }

    [Theory]
    [InlineData("nbss_len", true)]
    [InlineData("nbss_length", true)]
    [InlineData("foo_nbss_len_bar", true)]
    [InlineData("smb_len", false)]
    [InlineData(null, false)]
    public void IsNbssLengthField(string? name, bool expected) =>
        Assert.Equal(expected, NbssFraming.IsNbssLengthField(name));
}

public class ProjectKindsTests
{
    [Theory]
    [InlineData("http", true)]
    [InlineData("HTTPS", true)]
    [InlineData("tcp", false)]
    [InlineData(null, false)]
    public void IsHttp(string? kind, bool expected) => Assert.Equal(expected, ProjectKinds.IsHttp(kind));

    [Fact]
    public void NormalizeTransport_HttpsEnablesTls()
    {
        var p = new ProjectConfig { Name = "w", Kind = "https", Transport = new TransportConfig { Type = "tcp" } };
        ProjectKinds.NormalizeTransport(p);
        Assert.True(p.Transport.Tls);
        Assert.Equal("https", p.Transport.Type);
    }

    [Fact]
    public void NormalizeTransport_HttpRewritesFileType()
    {
        var p = new ProjectConfig { Name = "w", Kind = "http", Transport = new TransportConfig { Type = "file" } };
        ProjectKinds.NormalizeTransport(p);
        Assert.Equal("http", p.Transport.Type);
        Assert.False(p.Transport.Tls);
    }
}

public class ResponseMatcherTests
{
    [Fact]
    public void Matches_And_Describe()
    {
        Assert.True(ResponseMatcher.Matches(null, null));
        Assert.True(ResponseMatcher.Matches("HTTP/1.1 200"u8.ToArray(), "http/1.1"));
        Assert.False(ResponseMatcher.Matches(null, "x"));
        Assert.Equal("(no response)", ResponseMatcher.Describe(null));
        var longBody = Encoding.ASCII.GetBytes(new string('A', 200));
        Assert.EndsWith("…", ResponseMatcher.Describe(longBody, 50));
    }
}

public class DictionaryAndLoaderTests
{
    [Fact]
    public void BuildDictionaryTokens_HexAndEscapesAndComments()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-dict-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var dictPath = Path.Combine(dir, "d.txt");
            File.WriteAllText(dictPath, "# comment\nhex:DEAD\nhello\\nworld\n");
            var yaml = Path.Combine(dir, "p.yaml");
            File.WriteAllText(yaml, "name: p\nkind: file\ndictionary:\n  - hex:00FF\ndictionaryFile: d.txt\n");
            var project = ProjectLoader.Load(yaml);
            var tokens = BuiltInMutators.BuildDictionaryTokens(project, yaml);
            Assert.Contains(tokens, t => t.SequenceEqual(new byte[] { 0x00, 0xFF }));
            Assert.Contains(tokens, t => t.SequenceEqual(new byte[] { 0xDE, 0xAD }));
            Assert.Contains(tokens, t => Encoding.UTF8.GetString(t) == "hello\nworld");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void ProjectLoader_LoadFileText_AndDiscoverSkipsTemplate()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var yaml = Path.Combine(root, "projects", "file-text.yaml");
        var project = ProjectLoader.Load(yaml);
        Assert.Equal("file", project.Kind);
        Assert.False(string.IsNullOrWhiteSpace(project.DictionaryFile));

        var projectsDir = Path.Combine(root, "projects");
        var found = ProjectLoader.DiscoverProjects(projectsDir).ToList();
        Assert.DoesNotContain(found, p => Path.GetFileName(p).StartsWith("_TEMPLATE_", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(found, p => p.EndsWith("file-text.yaml", StringComparison.OrdinalIgnoreCase));
    }
}

public class BugHunterMistakesTests
{
    [Fact]
    public void Catalog_ChannelsAndTokens()
    {
        Assert.NotEmpty(BugHunterMistakes.ForChannel(HuntChannel.Oracle));
        Assert.NotEmpty(BugHunterMistakes.ForChannel(HuntChannel.Seed));
        var ids = BugHunterMistakes.All.Select(m => m.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        var tokens = BugHunterMistakes.DefaultDictionaryTokens();
        Assert.Contains("../", tokens);
        Assert.Contains(tokens, t => t.Contains("OR 1=1", StringComparison.Ordinal));
    }
}

public class OracleEngineTests
{
    [Fact]
    public async Task Evaluate_ExpectSubstringMiss_EmitsFinding()
    {
        var project = new ProjectConfig
        {
            Name = "o",
            Oracles = new OracleConfig
            {
                Enabled = true,
                PersistFindings = false,
                Invariants =
                [
                    new OracleInvariantRuleConfig
                    {
                        Id = "need-ok",
                        Type = "expectSubstring",
                        Pattern = "OK",
                        Severity = "violation",
                    },
                ],
            },
        };
        var obs = new OracleObservation(
            project, Path.GetTempPath(), "hi"u8.ToArray(),
            new TargetRunResult(false, 0, null, "ok", "NOPE"u8.ToArray()),
            "GET", "bitflip", 1, 0, 0, null, null);
        var result = await OracleEngine.EvaluateAsync(obs);
        Assert.NotEmpty(result.Findings);
        Assert.Contains(result.Findings, f => f.RuleId == "need-ok");
        Assert.NotEmpty(result.Needs);
    }

    [Fact]
    public async Task Evaluate_Disabled_Empty()
    {
        var project = new ProjectConfig { Name = "o", Oracles = new OracleConfig { Enabled = false } };
        var obs = new OracleObservation(
            project, Path.GetTempPath(), [] ,
            new TargetRunResult(false, 0, null, "ok"),
            null, null, 0, 0, 0, null, null);
        var result = await OracleEngine.EvaluateAsync(obs);
        Assert.Empty(result.Findings);
    }
}

public class DoctorHintTests
{
    [Theory]
    [InlineData("file-text", "../targets/file-text/app.exe", "build-file-text")]
    [InlineData("reeldeck", "../targets/reeldeck/reeldeck", "build-reeldeck")]
    [InlineData("vulnserver", "../targets/vulnserver/randall-vulnserver.exe", "vulnserver")]
    public void SuggestBuildHint_IsProjectAware(string name, string exe, string needle)
    {
        var p = new ProjectConfig { Name = name, Kind = "file", Target = new TargetConfig { Executable = exe } };
        Assert.Contains(needle, LabDoctor.SuggestBuildHint(p, "projects/x.yaml"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DoctorCheckPlatform_Classify()
    {
        Assert.Equal(PlatformScope.Linux, DoctorCheckPlatform.Classify("linux:gdb"));
        Assert.Equal(PlatformScope.Windows, DoctorCheckPlatform.Classify("procmon"));
        Assert.Equal(PlatformScope.Cross, DoctorCheckPlatform.Classify("target"));
    }
}

public class HttpCookieJarTests
{
    [Fact]
    public void Absorb_And_Apply_RoundTrip()
    {
        var jar = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var response = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/\r\nSet-Cookie: role=admin\r\n\r\nbody"u8.ToArray();
        HttpCookieJar.AbsorbSetCookie(jar, response);
        Assert.Equal("abc", jar["sid"]);
        Assert.Equal("admin", jar["role"]);

        var req = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"u8.ToArray();
        var withCookie = HttpCookieJar.ApplyCookieHeader(req, jar);
        var text = Encoding.ASCII.GetString(withCookie);
        Assert.Contains("Cookie:", text);
        Assert.Contains("sid=abc", text);
        Assert.Contains("role=admin", text);
    }

    [Fact]
    public void Apply_ReplacesExistingCookieHeader()
    {
        var jar = new Dictionary<string, string> { ["a"] = "1" };
        var req = "GET / HTTP/1.1\r\nHost: h\r\nCookie: old=x\r\n\r\n"u8.ToArray();
        var outBytes = HttpCookieJar.ApplyCookieHeader(req, jar);
        var text = Encoding.ASCII.GetString(outBytes);
        Assert.Contains("Cookie: a=1", text);
        Assert.DoesNotContain("old=x", text);
    }
}
