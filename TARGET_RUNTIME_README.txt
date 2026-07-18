================================================================================
RANDFUZZ — TARGET RUNTIME (complete next-gen track)
================================================================================
Date: 2026-07-18
Canonical: docs/TARGET_RUNTIME.md
Template: docs/templates/tcp-runtime.yaml

STATUS — DONE
-------------
A  TargetRuntimeService + /api/runtime/* + CLI + slot persistence
B  FuzzEngine longLived + target.agentUrl
C  TcpTube / UdpTube / StdioTube
D  Memory lens (fill/UAF, regions, neighborhood, crash UI)
E  Declarative postStart (wait-port/sleep/exec/tcp-send/udp-send/http-get)
F  Page Heap (gflags) + cdb !heap enrichment

HOW TO USE
----------
  randall runtime start -c projects/vulnserver.yaml
  randall runtime restart|stop <id>
  randall fuzz -c <project>          # uses runtime when longLived
  randall memory -i <crash-guid>
  randall memory --pid N

  Remote: randall agent --port 5000
  YAML:   target.agentUrl: http://vm:5000
  Inspect: GET /api/runtime/inspect?pid=N&agent=http://vm:5000

REMOTE LAB (dumps + lens + offline backup)
------------------------------------------
  For real dumps/lens: open http://vm:5000 and fuzz ON the agent UI
  (laptop + agentUrl alone does not capture remote minidumps).

  On agent after fuzz:
    randall crashes pack -p <project> [-o data/exports/pack.zip]

  On laptop later:
    randall crashes pull -a http://vm:5000 -p <project> --import
    # or: Bundles → Pull from remote agent / Import crash pack

  Pack includes: inputs, dumps, analysis, memory_lens, optional runs.

YAML HIGHLIGHTS
---------------
  target.pageHeap: true
  target.postStart:
    - op: wait-port
      port: 9999
    - op: exec
      command: powershell
      args: ["-File", "tools/open.ps1", "{pid}"]

MEMORY LENS
-----------
  Fill patterns FEEEFEEE/DDDDDDDD/…
  Link/unlink register hints
  cdb !heap when Debugging Tools installed
  UI: Crashes → Memory lens card

================================================================================
