# Точные команды воспроизведения

## Доступные команды из репозитория

- `go run ./cmd/firewall help`
- `go run ./cmd/arm-sim --list-scenarios`
- `make build`
- `make test`
- `make demo-local`
- `make stand-up` / `make stand-down` (если доступен Docker daemon)

## Локальный запуск, использованный для артефактов

1. Сборка:
   - `go build -o /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall ./cmd/firewall`
   - `go build -o /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim ./cmd/arm-sim`
2. PLC:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/venv/bin/python plc-sim/server.py --config /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/plc-config.json`
3. Firewall:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall run --config /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/config.yaml --policy /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.yaml --reload-interval 1s`
4. Сценарии клиента:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim --target 127.0.0.1:16020 --scenario normal-read`
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim --target 127.0.0.1:16020 --scenario repeated-write --repeat 10`
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim --target 127.0.0.1:16020 --scenario repeated-write --repeat 3000` для длительного прогона T9
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim --target 127.0.0.1:16020 --scenario rare-write`
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim --target 127.0.0.1:16020 --scenario forbidden-write`
5. Генерация policy:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall generate-policy --config /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/config.yaml --output /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.candidate.yaml --baseline-output /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.generated.yaml --write-threshold 2`
6. Валидация и применение:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall validate-policy --policy /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.candidate.yaml`
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall apply-policy --candidate /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.candidate.yaml --active /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.yaml`
7. Replay:
   - `/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall replay --config /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/config.yaml --policy /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/policy.candidate.yaml --output /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/reports/replay-report.json`
8. Проверка отсутствия рестарта:
   - `ps -p $(cat /Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/05_hot_reload/t8_firewall_pid_before.txt) -o pid=,ppid=,lstart=,command=`
   - сравнить файлы [t8_firewall_pid_before.txt](../05_hot_reload/t8_firewall_pid_before.txt) и [t8_firewall_pid_after.txt](../05_hot_reload/t8_firewall_pid_after.txt)
9. Проверка содержимого БД:
   - `python3 - <<'PY'`
     `import sqlite3; conn = sqlite3.connect("/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/events.db"); print(conn.execute("SELECT COUNT(*) FROM modbus_events").fetchone()[0]); conn.close()`
     `PY`
