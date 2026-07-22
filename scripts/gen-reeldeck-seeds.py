#!/usr/bin/env python3
"""Generate valid-ish .rndl seeds for ReelDeck (shallow → deep paths)."""
from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED_DIR = ROOT / "projects" / "seeds"


def u16(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def u32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def header(title: str, flags: int = 0, ver: int = 1) -> bytes:
    t = title.encode("utf-8")
    # magic + ver + flags + hdr_size + title_len + title
    body = u16(ver) + u16(flags) + u32(12 + 2 + len(t)) + u16(len(t)) + t
    return b"RNDL" + body


def track(fourcc: bytes, rate: int, data: bytes) -> bytes:
    assert len(fourcc) == 4
    return fourcc + u32(rate) + u32(len(data)) + data


def write(name: str, blob: bytes) -> None:
    SEED_DIR.mkdir(parents=True, exist_ok=True)
    path = SEED_DIR / name
    path.write_bytes(blob)
    print(f"wrote {path} ({len(blob)} bytes)")


def main() -> None:
    # 0) Shallow title overflow (BUG A) — lobby crash
    write(
        "reeldeck_title_boom.rndl",
        header("A" * 64, flags=0) + u16(0),
    )

    # 1) Minimal PCM — safe shallow path
    pcm_body = u32(8) + b"\x00\x01\x02\x03\x04\x05\x06\x07"
    write(
        "reeldeck_pcm.rndl",
        header("demo", flags=0) + u16(1) + track(b"PCM ", 44100, pcm_body),
    )

    # 2) MAD with sync + layer3 (no bug bitrate) — reaches decode_mad_layer3
    mad = bytes([0xFF, 0xE2, 0x40, 0x00]) + b"BR\x00\x00rest-of-frame"
    write(
        "reeldeck_mad.rndl",
        header("radio", flags=0) + u16(1) + track(b"MAD ", 48000, mad),
    )

    # 3) MAD bug-shaped (bitrate 0xF) — deep crash candidate
    mad_bug = bytes([0xFF, 0xE2, 0xF0, 0x00]) + b"frame"
    write(
        "reeldeck_mad_bug.rndl",
        header("static", flags=0) + u16(1) + track(b"MAD ", 48000, mad_bug),
    )

    # 4) VID I→P→X — deep exotic path
    def vframe(typ: bytes, payload: bytes) -> bytes:
        return typ + u32(len(payload)) + payload

    vid = vframe(b"I", b"intra") + vframe(b"P", b"pred") + vframe(b"X", b"EXOTIC_FILTER_NAME!!!!")
    write(
        "reeldeck_vid.rndl",
        header("clip", flags=0) + u16(1) + track(b"VID ", 30, vid),
    )

    # 5) META + playlist + studio EDIT — deepest studio path
    meta = b"ART " + u16(4) + b"Band" + b"CUE " + u16(4) + b"QQxx"
    studio = b"EDIT" + u16(1) + u16(5) + b"blur!" + u32(0) + u16(10) + b"RENDER\x00\x00\x00\x00"
    flags = 0x0001 | 0x0002  # STUDIO | PLAYLIST
    blob = (
        header("studio-mix", flags=flags)
        + u16(2)
        + track(b"META", 0, meta)
        + track(b"PCM ", 22050, u32(4) + b"abcd")
        + u16(2)
        + u16(0)
        + u16(1)
        + studio
    )
    write("reeldeck_studio.rndl", blob)

    # 6) Multi-track player-like file
    multi = (
        header("album", flags=0)
        + u16(3)
        + track(b"PCM ", 44100, pcm_body)
        + track(b"MAD ", 44100, mad)
        + track(b"META", 0, b"ALB " + u16(3) + b"LP1")
    )
    write("reeldeck_album.rndl", multi)


if __name__ == "__main__":
    main()
