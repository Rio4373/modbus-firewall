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
