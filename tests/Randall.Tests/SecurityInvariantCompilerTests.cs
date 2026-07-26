using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class SecurityInvariantCompilerTests
{
    [Fact]
    public void Compile_AuthSessionAfterLogin_MapsToRequireAuth()
    {
        var result = SecurityInvariantCompiler.Compile("ASSERT auth.session != null AFTER login");

        Assert.True(result.Ok);
        Assert.Single(result.Rules);
        var rule = result.Rules[0];
        Assert.Equal("auth.session", rule.Subject);
        Assert.Equal("!=", rule.Operator);
        Assert.Equal("null", rule.Expected);
        Assert.Equal("login", rule.Temporal);
        Assert.Equal("auth", rule.OracleRuleClass);
        Assert.Equal("requireAuth", rule.OracleRuleType);
        Assert.Equal("dictionary", rule.NeedRequest);
        Assert.Single(result.Needs);
        Assert.Equal("dictionary", result.Needs[0].Request);
        Assert.Equal("auth", result.Needs[0].RuleClass);
    }

    [Fact]
    public void Compile_ResponseStatus_MapsToForbidResponseClass()
    {
        var result = SecurityInvariantCompiler.CompileLines(
        [
            "ASSERT response.status != 500",
            "ASSERT auth.role == admin AFTER login",
        ]);

        Assert.True(result.Ok);
        Assert.Equal(2, result.Rules.Count);

        var status = result.Rules.First(r => r.Subject.Equals("response.status", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("invariant", status.OracleRuleClass);
        Assert.Equal("forbidResponseClass", status.OracleRuleType);
        Assert.Equal("response-class", status.AssertKind);

        var role = result.Rules.First(r => r.Subject.Equals("auth.role", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("auth", role.OracleRuleClass);
        Assert.Equal("forbidUntil", role.OracleRuleType);
        Assert.Equal("hunter", role.NeedRequest);
        Assert.Equal(2, result.Needs.Count);
    }

    [Fact]
    public void Compile_BadLine_ReportsError_StillCompilesGoodOnes()
    {
        var result = SecurityInvariantCompiler.CompileLines(
        [
            "ASSERT auth.session != null AFTER login",
            "NOT AN ASSERT",
            "# comment ignored",
        ]);

        Assert.True(result.Ok);
        Assert.Single(result.Rules);
        Assert.Single(result.Errors);
        Assert.Contains("unrecognized", result.Errors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryParseLine_ExistsOperator()
    {
        var rule = SecurityInvariantCompiler.TryParseLine("ASSERT response.body exists");
        Assert.NotNull(rule);
        Assert.Equal("exists", rule!.Operator);
        Assert.Equal("invariant", rule.OracleRuleClass);
    }
}
