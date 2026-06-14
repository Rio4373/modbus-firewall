# Dashboard video demonstration script

Цель ролика: показать промышленный Modbus TCP firewall как завершённый prototype monitoring system: анализ трафика, генерацию policy, фильтрацию, hot reload и эксплуатационные метрики.

## Запуск стенда

```bash
docker compose up --build
```

URL интерфейсов:

- Dashboard: <http://localhost:3000>
- Firewall dashboard API: <http://localhost:18080/api/overview>
- Modbus TCP firewall endpoint: `127.0.0.1:1502`

Полезные команды для отдельного терминала:

```bash
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario normal-read
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario repeated-write --repeat 10
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario rare-write
```

## Окна для записи

1. Браузер с dashboard на <http://localhost:3000>.
2. Терминал с `docker compose up --build`.
3. Терминал для команд `arm-sim`.
4. При необходимости отдельное окно с `artifacts/operational-tests/reports/operational_test_report.md`.

## Этап 1. Overview

Показать главный экран:

- `ONLINE`;
- режим `ANALYZE` или `FILTER`;
- uptime;
- PID;
- active connections;
- policy rules;
- processed/blocked requests;
- average latency;
- requests/sec.

Акцент: dashboard получает данные от работающего firewall через REST/SSE, а не показывает статичную картинку.

## Этап 2. ANALYZE

В dashboard нажать `ANALYZE`.

Запустить штатный трафик:

```bash
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario normal-read
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario repeated-write --repeat 10
```

Показать:

- строки `ALLOW` в Live Modbus Traffic;
- рост processed requests;
- накопление событий для policy generation.

## Этап 3. Generate Policy

Нажать `Generate Policy`.

Показать экран `Security Policy`:

- автоматически сформированные правила;
- function codes;
- source/destination;
- unit id;
- диапазоны регистров;
- содержимое `policy.yaml`.

Акцент: policy формируется из наблюдаемого легитимного трафика.

## Этап 4. Apply Policy

Нажать `Apply Policy`.

Показать:

- переход в `FILTER`;
- PID процесса не изменился;
- событие `policy_applied` в Events & Logs;
- hot reload применяет изменения без restart.

## Этап 5. Блокировка запрещённых операций

Запустить:

```bash
docker compose exec -T arm-sim arm-sim --target firewall:1502 --scenario forbidden-write
```

Показать:

- строку `BLOCK` красным в Live Modbus Traffic;
- рост blocked counter;
- событие blocked request в логах;
- отсутствие записи в PLC как смысловой вывод: firewall сформировал Modbus exception локально.

## Этап 6. Hot reload

Нажать `Reload Policy` или повторить `Apply Policy` после изменения candidate policy.

Показать:

- PID до/после одинаковый;
- событие `policy_reload` или `policy_reload_requested`;
- TCP exchange продолжается;
- новые правила применяются сразу.

## Этап 7. Метрики и результаты 500 000 requests

Открыть блок `Operational Metrics` и отчёт:

```text
artifacts/operational-tests/reports/operational_test_report.md
```

Показать ключевые показатели:

- обработанные запросы;
- avg latency;
- p95/p99;
- throughput;
- false positive;
- connection loss;
- recovery time;
- uptime;
- RAM/CPU metrics.

Для полного прогона перед записью:

```bash
BENCHMARK_REQUESTS=500000 make test-load
```

## Финальный тезис

Firewall работает как application-layer Modbus TCP proxy: в режиме анализа он накапливает профиль штатного обмена, затем формирует allow-list policy, в режиме фильтрации блокирует неразрешённые операции, а изменения policy применяются горячо без перезапуска процесса.
