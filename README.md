# Modbus TCP Firewall 

## Назначение проекта
`modbus-firewall` — TCP proxy фаервол для Modbus TCP.

Цель:
- прозрачно проксировать запросы ARM-клиента к PLC;
- в режиме `observe` собирать события в SQLite;
- генерировать политику на основе исторических событий;
- проверять политику офлайн через `replay`;
- применять политику в `enforce` без остановки сервиса (hot reload).

## Архитектура
Базовый поток трафика:
- `arm-sim` (Go) -> `firewall-proxy` (Go) -> `plc-sim` (PyModbus)

Логический конвейер:
1. Клиентский Modbus TCP запрос приходит в proxy.
2. Proxy парсит MBAP/PDU (FC 01,02,03,04,05,06,15,16).
3. В `observe` запрос всегда пересылается в PLC, событие сохраняется в SQLite.
4. В `enforce` запрос проверяется через policy matcher.
5. Разрешённый запрос пересылается в PLC, запрещённый блокируется локально.

## Режимы работы
- `observe`
  - DPI только анализирует и логирует события.
  - Блокировки Modbus операций нет.
- `enforce`
  - `deny all` по умолчанию.
  - Разрешение только по правилам `policy.yaml`.
  - Ошибка парсинга запроса приводит к безопасному отказу (`safe deny`).
- `replay` (офлайн-команда)
  - Читает исторические события из SQLite.
  - Прогоняет события через matcher и строит отчёт покрытия.

## Структура проекта
```text
cmd/firewall/               # CLI
cmd/arm-sim/                # ARM simulator / test client CLI
internal/armsim/            # сценарии ARM-клиента и Modbus TCP клиент
internal/config/            # загрузка и валидация config.yaml
internal/modbus/            # parser Modbus TCP
internal/storage/           # SQLite storage 
internal/policy/            # policy model, loader, matcher, apply/reset
internal/proxy/             # TCP proxy, observe/enforce, hot reload
internal/generator/         # генерация policy из событий
internal/replay/            # офлайн replay анализ
internal/logging/           # slog logger
plc-sim/                    # PLC simulator на PyModbus
configs/                    # рабочие config/policy
configs/examples/           # example config/policy
docs/DEMO.md                # пошаговое демо
```

## Конфигурация
Рабочие файлы:
- `./configs/config.yaml`
- `./configs/policy.yaml`

Примеры:
- `./configs/examples/config.example.yaml`
- `./configs/examples/policy.example.yaml`

## Команды запуска
Make targets:
- `make build`
- `make test`
- `make run-observe`
- `make run-enforce`
- `make generate-policy`
- `make validate-policy`
- `make replay`
- `make reset-candidate`
- `make apply-policy`
- `make stand-up`
- `make stand-down`
- `make stand-logs`
- `make stand-arm-normal`
- `make stand-arm-repeated`
- `make stand-arm-rare`
- `make stand-arm-forbidden`
- `make demo-all`
- `make demo-showcase`
- `make demo-prepare`
- `make demo-observe`
- `make demo-generate-policy`
- `make demo-replay`
- `make demo-enforce`
- `make demo-hot-reload`

CLI:
- `firewall run --config ./configs/config.yaml --mode observe --reload-interval 1s`
- `firewall run --config ./configs/config.yaml --mode enforce --policy ./configs/policy.yaml --reload-interval 1s`
- `firewall validate-config --config ./configs/config.yaml`
- `firewall generate-policy --config ./configs/config.yaml --output ./configs/policy.candidate.yaml --baseline-output ./configs/policy.generated.yaml --write-threshold 2`
- `firewall validate-policy --policy ./configs/policy.candidate.yaml`
- `firewall replay --config ./configs/config.yaml --policy ./configs/policy.candidate.yaml --output ./reports/replay-report.json`
- `firewall reset-candidate --baseline ./configs/policy.generated.yaml --candidate ./configs/policy.candidate.yaml`
- `firewall apply-policy --candidate ./configs/policy.candidate.yaml --active ./configs/policy.yaml`

ARM simulator / test client:
- `go run ./cmd/arm-sim --list-scenarios`
- `go run ./cmd/arm-sim --target 127.0.0.1:1502 --scenario normal-read`
- `go run ./cmd/arm-sim --target 127.0.0.1:1502 --scenario repeated-write --repeat 10`
- `go run ./cmd/arm-sim --target 127.0.0.1:1502 --scenario rare-write`
- `go run ./cmd/arm-sim --target 127.0.0.1:1502 --scenario forbidden-write`

PLC simulator (PyModbus):
- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r plc-sim/requirements.txt`
- `python plc-sim/server.py --config plc-sim/config.json`

## ARM simulator / test client
`arm-sim` имитирует инженера АРМ и всегда подключается к адресу firewall proxy (`--target`).

Поддерживаемые сценарии:
- `normal-read`
  - FC `03` (Read Holding Registers), типичные безопасные read-запросы.
- `repeated-write`
  - FC `06` (Write Single Register), повторяющиеся write-операции в один диапазон.
- `rare-write`
  - FC `16` (Write Multiple Registers), редкая/единичная write-операция.
- `forbidden-write`
  - FC `06` в адрес, который обычно не покрыт allow-правилами (для проверки блокировки в `enforce`).

Базовые параметры:
- `--target` адрес firewall proxy (например `127.0.0.1:1502`)
- `--scenario` имя сценария
- `--unit-id` Modbus Unit ID (по умолчанию `1`)
- `--timeout` таймаут операции (по умолчанию `3s`)
- `--repeat` число повторов для `repeated-write` (по умолчанию `5`)

## PLC simulator (PyModbus)
`plc-sim` — минимальный Modbus TCP сервер для стенда.

Поддерживает:
- регистры `holding` и `input`;
- FC `03`, `04`, `06`, `16`;
- начальные значения регистров из JSON-конфига;
- логирование операций чтения/записи.

Основной запуск:
- `python plc-sim/server.py --config plc-sim/config.json`

Подробные инструкции: [plc-sim/README.md](./plc-sim/README.md)

## Docker Compose стенд
В корне проекта добавлен `docker-compose.yml` для воспроизводимого стенда:
- `plc-sim` (PyModbus)
- `firewall` (Go)
- `arm-sim` (Go)

Сетевой поток:
- `arm-sim (10.10.0.2) -> firewall (10.10.0.4:1502) -> plc-sim (10.10.0.3:502)`

Быстрый запуск:
- `make stand-up`

Логи:
- `make stand-logs`

Запуск сценариев arm-sim в стенде:
- `make stand-arm-normal`
- `make stand-arm-repeated`
- `make stand-arm-rare`
- `make stand-arm-forbidden`

Остановка:
- `make stand-down`

Подробно: [deployments/docker-compose/README.md](./deployments/docker-compose/README.md)

## Demo сценарии стенда
Для полного воспроизводимого прогона всех этапов:
- `make demo-all`

Для автоматического демонстрационного прогона с поясняющим выводом и итоговым отчётом:
- `make demo-showcase`
  - Отчёт сохраняется в `./reports/demo-showcase-report.txt`
  - По умолчанию стенд после завершения автоматически останавливается

Пошагово:
- `make demo-prepare`
- `make demo-observe`
- `make demo-generate-policy`
- `make demo-replay`
- `make demo-enforce`
- `make demo-hot-reload`

Подробные ожидаемые результаты каждого шага: [docs/DEMO.md](./docs/DEMO.md)

## Пример сценария observe -> generate-policy -> replay -> enforce
1. Запустить firewall в `observe`:
   - `make run-observe`
2. Сгенерировать трафик из клиента (ARM sim) через firewall в PLC.
3. Сгенерировать candidate policy из SQLite:
   - `make generate-policy`
4. Проверить candidate policy:
   - `make validate-policy`
5. Прогнать replay для оценки покрытия:
   - `make replay`
6. Если replay не устраивает, откатить ручные правки candidate:
   - `make reset-candidate`
7. Применить candidate как active policy:
   - `make apply-policy`
8. Запустить firewall в `enforce`:
   - `make run-enforce`

Если proxy уже запущен с `--reload-interval`, новая active policy подхватывается без рестарта.

## Порог K для write-операций
- Задаётся флагом `--write-threshold` в `generate-policy`.
- Применяется только к write (FC 05,06,15,16).
- В policy включаются только write-диапазоны с частотой `>= K`.
- Значение по умолчанию: `K=2`.
- Для read (FC 01,02,03,04) выполняется merge соседних/пересекающихся диапазонов.

## Ограничения MVP
- Нет CIDR/подсетей в policy matcher, только точные IP.
- Нет TLS/mTLS и аутентификации между компонентами.
- Нет полноценного rate limiting/DoS защиты.
- Нет кластерного режима и распределённого хранилища.
- SQLite используется как локальное хранилище для одного инстанса.

## Demo instructions
Подробный сценарий демо: [docs/DEMO.md](./docs/DEMO.md)

## Качество и проверки
- Unit/integration tests: `go test ./...`
- Стиль и формат: `gofmt -w` (при изменениях)
