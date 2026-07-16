# FTP simple example

Port of [boofuzz ftp_simple.py](https://github.com/jtpereyda/boofuzz/blob/master/examples/ftp_simple.py).

Uses **exhaustive** mode — walks commands × fields × mutators like `session.fuzz()`.

```powershell
..\..\scripts\build-vulnftp.ps1
randall fuzz -c project.yaml --dry-run
randall fuzz -c ..\..\projects\vulnftp.yaml
```
