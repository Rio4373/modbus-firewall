# Docker Compose Stand

`docker-compose.yml` в корне поднимает воспроизводимый стенд из 3 компонентов:
- `plc-sim` (PyModbus)
- `firewall` (Go)
- `arm-sim` (Go)

Сетевой поток:
- `arm-sim (10.10.0.2) -> firewall (10.10.0.4:1502) -> plc-sim (10.10.0.3:502)`

## Что монтируется в firewall
- `./configs:/app/configs` — `config.yaml`, `policy.yaml`
- `./data:/app/data` — SQLite events DB
- `./reports:/app/reports` — replay отчёты

## Базовые команды
```bash
docker compose up --build -d
docker compose logs -f plc-sim firewall
docker compose down
```

## Сценарии arm-sim внутри стенда
```bash
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario normal-read
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario repeated-write --repeat 10
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario rare-write
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write
```

## Команды firewall внутри стенда
```bash
docker compose exec -T firewall firewall generate-policy \
  --config ./configs/config.yaml \
  --output ./configs/policy.candidate.yaml \
  --baseline-output ./configs/policy.generated.yaml \
  --write-threshold 2

docker compose exec -T firewall firewall validate-policy --policy ./configs/policy.candidate.yaml

docker compose exec -T firewall firewall replay \
  --config ./configs/config.yaml \
  --policy ./configs/policy.candidate.yaml \
  --output ./reports/replay-report.json

docker compose exec -T firewall firewall apply-policy \
  --candidate ./configs/policy.candidate.yaml \
  --active ./configs/policy.yaml
```

## Готовые demo-скрипты
В репозитории есть сценарии end-to-end:
- `scripts/demo/00_prepare.sh`
- `scripts/demo/01_observe.sh`
- `scripts/demo/02_generate_policy.sh`
- `scripts/demo/03_replay.sh`
- `scripts/demo/04_enforce.sh`
- `scripts/demo/05_hot_reload.sh`
- `scripts/demo/run_all.sh`

Запуск полного демо:
```bash
make demo-all
```
