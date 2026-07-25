using Randall.Infrastructure;
using Xunit;
namespace Randall.Tests;
public class LineageChainBuilderTests {
  [Fact] public void BuildFromParent_MergesWithoutDuplicateTail() {
    var lineage = new Dictionary<string, IReadOnlyList<string>> { ["p"] = ["dictionary", "integer"] };
    Assert.Equal(["dictionary", "integer", "splice"], LineageChainBuilder.BuildFromParent("p", lineage, ["integer", "splice"]));
  }
}
