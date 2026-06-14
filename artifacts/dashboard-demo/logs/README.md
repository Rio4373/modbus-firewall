# Demo logs

This directory is reserved for video demonstration logs.

Recommended capture commands:

```bash
docker compose logs -f firewall dashboard plc-sim
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write
```
