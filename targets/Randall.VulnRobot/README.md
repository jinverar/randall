# Randall.VulnRobot

Fictional **RBT1** robot-arm lab — TCP motion (HELLO / JOINT / TRAJ / TOOL) and UDP telemetry (pose / force / diag) with intentional length-field crashes.

**Not** ROS, URScript, Fanuc, ABB, KUKA, EtherCAT, or any real pendant/fieldbus. Loopback by default.

```bash
randall-vulnrobot --mode tcp -p 15560
randall-vulnrobot --mode udp -p 15561
```

See [docs/ROBOT_LAB.md](../../docs/ROBOT_LAB.md).
