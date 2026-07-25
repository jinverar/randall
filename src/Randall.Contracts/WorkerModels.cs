namespace Randall.Contracts;

/// <summary>
/// Optional ingest surface for external fuzz workers (AFL++, LibAFL, WinAFL) to publish
/// normalized observations into a Randfuzz run. Full adapters are out of scope — this is the
/// contract stub; see docs/EXTERNAL_WORKERS.md.
/// </summary>
public interface IExternalWorkerIngest
{
    /// <summary>Worker identifier: aflpp, libafl, winafl, honggfuzz, …</summary>
    string WorkerKind { get; }

    /// <summary>Publish a coverage/path/crash/oracle-shaped observation from the worker.</summary>
    void IngestObservation(Observation observation);

    /// <summary>Publish a normalized fault when the worker detects a crash or sanitizer report.</summary>
    void IngestFault(FaultSignal signal, string? inputHash = null, int iteration = 0);
}

/// <summary>
/// Bridges an external worker stream into an in-process <see cref="ObservationBus"/>.
/// Used by engine adapters and future LibAFL/WinAFL companions.
/// </summary>
public sealed class ExternalWorkerObservationBridge(ObservationBus bus, string workerKind) : IExternalWorkerIngest
{
    public string WorkerKind { get; } = workerKind;

    public void IngestObservation(Observation observation) => bus.Publish(observation);

    public void IngestFault(FaultSignal signal, string? inputHash = null, int iteration = 0)
    {
        bus.Publish(ObservationEvents.Fault(
            runId: $"worker:{WorkerKind}",
            iteration,
            inputHash ?? "",
            signal,
            project: null));
    }
}
