# HTTP simple example

Port of [boofuzz http_simple.py](https://github.com/jtpereyda/boofuzz/blob/master/examples/http_simple.py).

```powershell
# With Randall VulnHttp lab target:
..\..\scripts\build-vulnhttp.ps1
randall fuzz -c project.yaml --dry-run
randall fuzz -c ..\..\projects\vulnhttp.yaml
```

Without a target, `randall doctor` warns — start any HTTP server on `127.0.0.1:8080` or use VulnHttp.
