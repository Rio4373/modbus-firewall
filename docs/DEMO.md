# Demo Instructions (End-to-End Stand)

## Цель
Показать воспроизводимый сценарий стенда:
1. `observe` собирает события в SQLite.
2. `generate-policy` строит policy из истории.
3. `replay` проверяет покрытие policy.
4. `enforce` пропускает штатные операции и блокирует запрещённые.
5. `hot reload` меняет политику без остановки firewall.

## Предпосылки
- Docker Desktop / Docker Engine
- Docker Compose V2 (`docker compose`)

## Быстрый запуск всех сценариев
```bash
make demo-all
```

## Автоматический демонстрационный прогон с комментариями
Если нужен один сценарий без ручного просмотра логов, используйте:

```bash
make demo-showcase
```

Что делает этот сценарий:
- сам поднимает стенд;
- прогоняет весь цикл `observe -> generate-policy -> replay -> enforce -> hot reload`;
- печатает поясняющий вывод по каждому шагу;
- автоматически показывает ключевые артефакты и подтверждения;
- отдельно показывает признаки живого прогона:
  - время запуска контейнеров;
  - пустое состояние SQLite до трафика;
  - свежие временные метки артефактов (`events.db`, `policy.candidate.yaml`, `replay-report.json`);
- сохраняет итоговый отчёт в `reports/demo-showcase-report.txt`;
- по умолчанию сам останавливает стенд и восстанавливает исходные `config.yaml` и `policy.yaml`.

Если нужно оставить стенд запущенным после завершения:

```bash
KEEP_STAND_UP=1 make demo-showcase
```

## Проверенный Docker Compose сценарий
Ниже сценарий, который был реально прогнан через `make demo-all`.

Команды:
```bash
cd /Users/maratbagautdinov/Desktop/modbus-firewall
make demo-all
docker compose ps
cat reports/replay-report.json
docker compose logs --tail=80 firewall plc-sim
python3 - <<'PY'
import sqlite3
path = "data/events.db"
conn = sqlite3.connect(path)
cur = conn.cursor()
print("count =", cur.execute("select count(*) from modbus_events").fetchone()[0])
print("by_fc =", cur.execute("select function_code, count(*) from modbus_events group by function_code order by function_code").fetchall())
conn.close()
PY
```

Что подтверждает успешный прогон:
- `docker compose ps` показывает `arm-sim`, `firewall`, `plc-sim` в статусе `Up`.
- `reports/replay-report.json` содержит `total_events=14`, `covered_events=13`, `blocked_events=1`.
- `data/events.db` содержит итоговые события демо-цепочки.
- `docker compose logs firewall plc-sim` показывает:
  - старт `firewall` в `observe`;
  - `hot reload успешно применен previous_mode=observe new_mode=enforce`;
  - блокировку `forbidden-write`;
  - повторный `hot reload` без рестарта;
  - успешный write на `plc-sim` после новой policy.

Ожидаемые артефакты после полного прогона:
- `configs/policy.candidate.yaml`
- `configs/policy.generated.yaml`
- `configs/policy.yaml`
- `data/events.db`
- `reports/replay-report.json`

## Локальный проверенный запуск без Docker
В текущем репозитории есть единый локальный e2e-скрипт:

```bash
make demo-local
```

Что делает скрипт:
- собирает локальные бинарники `firewall` и `arm-sim`;
- поднимает `plc-sim` через локальный Python venv;
- запускает цепочку `observe -> generate-policy -> replay -> apply-policy -> enforce -> hot reload`;
- печатает пути к артефактам (`config`, `policy`, `SQLite`, `replay-report`, `firewall.log`, `plc-sim.log`).

Этот путь полезен, когда Docker Compose недоступен или нужен быстрый автономный прогон на одной машине.

## Пошаговый запуск
```bash
make demo-prepare
make demo-observe
make demo-generate-policy
make demo-replay
make demo-enforce
make demo-hot-reload
```

## Что делает каждый сценарий и что ожидать

### 1) Observe (`make demo-observe`)
Действия:
- `arm-sim` отправляет `normal-read`, `repeated-write`, `rare-write` через `firewall`.
- `firewall` в режиме `observe` записывает события в SQLite.

Ожидаемый результат:
- В консоли видны `OK` ответы от `arm-sim`.
- Скрипт показывает `Событий в SQLite: ...` (минимум `14`).

### 2) Generate-policy (`make demo-generate-policy`)
Действия:
- Из `data/events.db` генерируется:
  - `configs/policy.candidate.yaml`
  - `configs/policy.generated.yaml`
- Выполняется валидация candidate policy.

Ожидаемый результат:
- Оба файла созданы.
- Скрипт показывает количество правил `>= 1`.

### 3) Replay (`make demo-replay`)
Действия:
- Candidate policy прогоняется по историческим событиям.
- Формируется `reports/replay-report.json`.

Ожидаемый результат:
- В отчёте есть `total_events > 0`.
- Для демо ожидается минимум один `blocked_events` (редкая запись не попадает в policy при `K=2`).

### 4) Enforce (`make demo-enforce`)
Действия:
- `config.yaml` переключается в `mode: enforce`.
- Candidate policy применяется как active policy.
- Проверяются 2 сценария:
  - `normal-read` (должен пройти)
  - `forbidden-write` (должен блокироваться)

Ожидаемый результат:
- Для `normal-read` в выводе есть `-> OK`.
- Для `forbidden-write` в выводе есть `BLOCKED/EXCEPTION`.

### 5) Hot reload (`make demo-hot-reload`)
Действия:
- Готовится новая candidate policy, где добавлено allow-правило для `forbidden-write`.
- Policy применяется атомарно через `apply-policy`.
- Без рестарта firewall повторяется `forbidden-write`.

Ожидаемый результат:
- ID контейнера `firewall` не меняется (перезапуска нет).
- `forbidden-write` после подмены policy проходит (`-> OK`).

## Полезные команды
```bash
make stand-up
make stand-logs
make stand-down
```

Локальные demo-скрипты:
- `scripts/demo/00_prepare.sh`
- `scripts/demo/01_observe.sh`
- `scripts/demo/02_generate_policy.sh`
- `scripts/demo/03_replay.sh`
- `scripts/demo/04_enforce.sh`
- `scripts/demo/05_hot_reload.sh`
- `scripts/demo/run_all.sh`
