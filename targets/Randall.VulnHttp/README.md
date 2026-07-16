# Randall VulnHttp

Minimal HTTP/1.1 server for Randall lab fuzzing. Default port **8080**.

Build: `../../scripts/build-vulnhttp.ps1`

Fuzz: `randall fuzz -c projects/vulnhttp.yaml`

**LAB USE ONLY** — intentional stack overflows in URI, headers, and POST body parsing.
