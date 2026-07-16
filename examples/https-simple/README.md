# HTTPS / TLS example

Template for fuzzing TLS services (boofuzz `fuzz_ssl_client.py` style).

```yaml
transport:
  tls: true
  tlsInsecure: true   # lab only — accept self-signed certs
  tlsHost: localhost  # SNI
```

```powershell
randall fuzz -c project.yaml --dry-run
# Point host/port at your HTTPS target when ready
```
