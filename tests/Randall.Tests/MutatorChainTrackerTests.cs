using Randall.Infrastructure;
using Xunit;
namespace Randall.Tests;
public class MutatorChainTrackerTests {
  [Fact] public void RecordLineage_CreditsPairsTriples() {
    var tracker = new MutatorChainTracker(null, true);
    tracker.RecordLineage(["dictionary", "integer", "splice"], 2, true);
    Assert.Contains(tracker.SnapshotRows(), r => r.DisplayLabel == "dictionary→integer→splice");
  }
  [Fact] public void SaveLoad_RoundTripsStore() {
    var dir = Path.Combine(Path.GetTempPath(), "rc-" + Guid.NewGuid().ToString("N"));
    var path = Path.Combine(dir, "mutator_chains.json");
    try {
      var t = new MutatorChainTracker(path, true);
      t.RecordLineage(["havoc", "splice"], 1, false); t.Save();
      Assert.Equal("havoc→splice", new MutatorChainTracker(path, true).SnapshotRows()[0].DisplayLabel);
    } finally { try { Directory.Delete(dir, true); } catch { } }
  }
}
