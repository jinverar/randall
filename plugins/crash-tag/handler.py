"""RPP post_crash — tag crash type for triage."""
import base64
import json
import sys


def classify(exit_code, detail: str, payload_len: int) -> str:
    detail_l = detail.lower()
    if exit_code is not None and int(exit_code) < 0:
        return "access_violation"
    if "stack" in detail_l or payload_len > 512:
        return "probable_overflow"
    if "timeout" in detail_l or "hang" in detail_l:
        return "hang"
    return "unknown"


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("op") != "post_crash":
            continue
        raw = req.get("input") or ""
        payload = base64.b64decode(raw) if raw else b""
        tag = classify(req.get("exitCode"), req.get("detail") or "", len(payload))
        print(json.dumps({"tag": tag, "name": "crash-tag"}), flush=True)


if __name__ == "__main__":
    main()
