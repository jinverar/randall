#!/usr/bin/env python3
"""Minimal boofuzz-shaped FTP example for scripts/import-boofuzz.py (fixture — not runnable).

Mirrors Request / session.connect patterns from boofuzz examples/ftp_simple.py.
"""

Request(
    "user",
    children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="user", default_value="anonymous"),
        Static(name="crlf", default_value="\r\n"),
    ),
)

Request(
    "pass",
    children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="pass", default_value="ftp"),
        Static(name="crlf", default_value="\r\n"),
    ),
)

Request(
    "stor",
    children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="filename", default_value="AAAA"),
        Static(name="crlf", default_value="\r\n"),
    ),
)

session.connect("user")
session.connect("user", "pass")
session.connect("pass", "stor")
