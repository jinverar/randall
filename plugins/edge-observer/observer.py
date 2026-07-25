"""RPP observe — publish custom novelty / fault hints to the observation bus."""
import base64
import json
import sys


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("op") != "observe":
            continue

        new_edges = int(req.get("newEdges") or 0)
        total_edges = int(req.get("totalEdges") or 0)
        detail = (req.get("detail") or "").lower()

        if new_edges >= 3:
            print(
                json.dumps(
                    {
                        "novelty": min(1.0, new_edges / 10.0),
                        "confidence": 0.7,
                        "severity": "info",
                        "note": f"edge-observer: +{new_edges} edges (total {total_edges})",
                        "name": "edge-observer",
                    }
                ),
                flush=True,
            )
            continue

        if "asan" in detail or "sanitizer" in detail:
            print(
                json.dumps(
                    {
                        "signal": "sanitizer",
                        "confidence": 0.85,
                        "severity": "high",
                        "note": "edge-observer saw sanitizer text in target detail",
                        "name": "edge-observer",
                    }
                ),
                flush=True,
            )
            continue

        print(json.dumps({"note": "edge-observer: quiet", "name": "edge-observer"}), flush=True)


if __name__ == "__main__":
    main()
