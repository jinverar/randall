using Randall.Contracts;
using Randall.Core.Model;

namespace Randall.Infrastructure;

public static class FuzzDependencyPolicies
{
    public static (LengthPolicy Length, ChecksumPolicy Checksum, int LengthDelta, int ChecksumDelta)
        Resolve(FuzzConfig fuzz)
    {
        var length = DependencyPolicyParser.ParseLength(fuzz.LengthPolicy, fuzz.SyncLengthFields);
        var checksum = DependencyPolicyParser.ParseChecksum(fuzz.ChecksumPolicy);
        return (length, checksum, fuzz.LengthPolicyDelta, fuzz.ChecksumPolicyDelta);
    }
}
