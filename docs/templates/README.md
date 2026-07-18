# Project YAML templates

Copy a template into `projects/` or `projects/local/`, then edit `name:`, host/port, seeds, and mutators.

| File | Kind | Use when |
|------|------|----------|
| [tcp.yaml](tcp.yaml) | TCP | Remote or local TCP service |
| [udp.yaml](udp.yaml) | UDP | Datagram service |
| [file.yaml](file.yaml) | File | CLI/parser that takes a file path |

The YAML **`name:`** field is the label shown in the web UI **Target profile** dropdown.

```powershell
copy docs\templates\tcp.yaml projects\local\myservice.yaml
# edit name: / host / port / seeds…
randall targets
randall fuzz -c projects/local/myservice.yaml --dry-run
```

Or use the UI / CLI wizard:

```powershell
randall case new --name myservice --kind tcp --host 127.0.0.1 --port 8080
```

Full guide: [CUSTOM_TARGETS.md](../CUSTOM_TARGETS.md) · seeds: [CASE_BUILDER.md](../CASE_BUILDER.md)

Also available as `projects/_TEMPLATE_tcp.yaml` (underscore prefix = not listed as a live target).
