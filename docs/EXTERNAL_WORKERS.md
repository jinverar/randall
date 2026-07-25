# External fuzz workers (observation ingest)

Randfuzz’s **brain** stays in Randall (oracles, scream intelligence, stalk map). External engines are **workers** that grind coverage when you need throughput — they publish into the same **observation bus** instead of replacing triage UX.

| Worker | Status | Randfuzz integration |
|--------|--------|----------------------|
| **AFL++** | ✅ Linux adapter | `fuzz.engine: aflpp` — see [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) |
| **honggfuzz** | ✅ Linux adapter | `fuzz.engine: honggfuzz` |
| **LibAFL** | 📄 contract stub | `IExternalWorkerIngest` — no full port |
| **WinAFL** | 📄 contract stub | ingest API only — Windows uses Randall engine + warm workers by default |

## Contract stub

```csharp
public interface IExternalWorkerIngest
{
    string WorkerKind { get; }
    void IngestObservation(Observation observation);
    void IngestFault(FaultSignal signal, string? inputHash = null, int iteration = 0);
}
```

`ExternalWorkerObservationBridge` wraps an in-process `ObservationBus` for engine adapters and future companions.

## Typical ingest flow

```text
External worker (AFL++/LibAFL/WinAFL campaign)
      ↓  stdout / queue / crash dir watcher
Adapter normalizes → Observation + FaultSignal
      ↓
IExternalWorkerIngest → ObservationBus
      ↓
Oracle score · mutator credit · scream catalog (crashes still land in data/crashes/)
```

### AFL++ (shipped)

Crashes and queue corpora sync back after `afl-fuzz` exits. Observations during the campaign are **not** streamed live today — post-run catalog + crash sidecars carry intelligence.

### LibAFL (planned)

LibAFL fuzzers can emit custom observers (coverage maps, sanitizer hooks). A thin companion would:

1. Map sancov / CmpLog / crash metadata → `ObservationEvents.Coverage` / `Fault`
2. Forward through `ExternalWorkerObservationBridge`
3. Persist crashes into `data/crashes/<project>/` with existing sidecar shape

No LibAFL dependency is added to the solution — only this ingest surface.

### WinAFL (planned)

WinAFL targets DynamoRIO + optional persistent mode on Windows. Randfuzz does **not** ship a WinAFL fork-server default; when needed, a companion would:

1. Watch WinAFL crash folders / bitmap updates
2. Ingest faults via `FaultSignalMapper`-compatible fields (AV, hang, sanitizer text)
3. Hand off to Investigation / scream canisters

Use `fuzz.engine: randall` for session/TCP labs; WinAFL remains an optional worker for file/DynamoRIO harnesses you already built.

## RPP observe vs external workers

| Mechanism | Scope |
|-----------|--------|
| **RPP `observe`** | Per-iteration child process on the Randall engine loop |
| **External worker ingest** | Separate grinder process; batch or streaming bridge |

Both publish `Observation` / `FaultSignal` — pick RPP for lightweight custom sensors; pick AFL++/LibAFL when you need their schedulers.

## Related

- [ENGINE_ADAPTERS.md](ENGINE_ADAPTERS.md) — AFL++/honggfuzz YAML
- [FAULT_SIGNALS.md](FAULT_SIGNALS.md) — unified fault taxonomy
- [ORACLES.md](ORACLES.md) — oracle stack consumes observations
