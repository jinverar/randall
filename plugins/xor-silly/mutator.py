import base64
import json
import random
import sys


def mutate(data: bytearray) -> None:
    """Tricky-ish mutations: xor a byte, insert a format string, or repeat a run."""
    if not data:
        data.extend(b"AAAA")
        return
    choice = random.randint(0, 2)
    if choice == 0:
        data[random.randrange(len(data))] ^= random.choice([0xFF, 0x7F, 0x80])
    elif choice == 1 and len(data) < 4000:
        data.extend(b"%s%s%s%n")
    elif len(data) < 4000:
        i = random.randrange(len(data))
        run = bytes([data[i]]) * random.randint(4, 64)
        data[i:i] = run


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("op") != "mutate":
            continue
        raw = base64.b64decode(req["input"])
        data = bytearray(raw)
        mutate(data)
        resp = {
            "output": base64.b64encode(bytes(data)).decode("ascii"),
            "name": "xor-silly",
        }
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
