# Modbus Firewall Dashboard Demo Guide

## Start

```bash
docker compose up --build
```

Open:

- Dashboard: http://localhost:3000
- API health: http://localhost:18080/api/health

## Demo traffic

```bash
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario normal-read
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario repeated-write --repeat 10
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write
```

## Video checkpoints

1. Overview shows ONLINE firewall, mode, PID, uptime and counters.
2. Live Modbus Traffic receives ALLOW rows in real time.
3. Generate Policy creates candidate allow-list from observed traffic.
4. Apply Policy switches to FILTER and keeps the same PID.
5. Forbidden write is shown as red BLOCK row.
6. Reload Policy records hot reload event.
7. Metrics panel and operational test report provide quantitative evidence.

## Thesis artifacts

- Dashboard screenshots: `artifacts/dashboard-demo/screenshots/`
- Demo logs: `artifacts/dashboard-demo/logs/`
- Operational benchmark report: `artifacts/operational-tests/reports/operational_test_report.md`
