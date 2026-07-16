"""RPP post_receive — classify FTP responses for Randall session flows."""
import base64
import json
import sys


def classify(response_text: str) -> dict:
    text = response_text.upper()
    if text.startswith("220"):
        return {"action": "continue", "note": "banner"}
    if text.startswith("331"):
        return {"action": "continue", "note": "need_pass"}
    if text.startswith("230"):
        return {"action": "continue", "note": "logged_in"}
    if text.startswith("5"):
        return {"action": "abort", "note": "ftp_error"}
    return {"action": "continue", "note": "ok"}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("op") != "post_receive":
            continue
        raw = req.get("response") or ""
        text = base64.b64decode(raw).decode("ascii", errors="replace") if raw else ""
        resp = classify(text)
        resp["name"] = "ftp-response"
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
