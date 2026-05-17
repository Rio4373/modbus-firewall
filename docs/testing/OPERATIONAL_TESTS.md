# Эксплуатационные и нагрузочные испытания

Основной автоматизированный раннер: `scripts/testing/operational_benchmark.py`.

Он поднимает воспроизводимый локальный стенд:

- встроенный PLC-эмулятор Modbus TCP без внешних Python-зависимостей;
- собранный бинарь `bin/firewall`;
- raw Modbus TCP клиент, генерирующий FC01, FC03, FC05, FC06, FC15, FC16;
- временные конфигурации и policy в `artifacts/operational-tests/runtime`.

## Запуск

```bash
make operational-smoke
make test-load
make benchmark
STABILITY_SECONDS=43200 make test-reliability
```

Через Docker Compose:

```bash
docker compose --profile testing run --rm operational-tests
```

Для сокращённого прогона можно переопределить параметры:

```bash
BENCHMARK_REQUESTS=10000 LATENCY_REQUESTS=1000 STABILITY_SECONDS=120 make test-load
```

Для полного нагрузочного испытания значение по умолчанию `BENCHMARK_REQUESTS=500000`.

## Сценарии

| Сценарий | Проверяемое свойство | Основные артефакты |
| --- | --- | --- |
| `load-500k-mixed` | 500 000 смешанных разрешённых и запрещённых запросов, latency, p95/p99, throughput | `csv/load_requests.csv`, `json/load_summary.json`, `charts/throughput.svg`, `charts/load_latency.png` |
| `false-positive-legitimate` | отсутствие ложных блокировок allow-list трафика | `csv/false_positive.csv`, `json/false_positive.json` |
| `forbidden-operations` | блокировка запрещённых регистров, FC, source IP и некорректных параметров | `csv/forbidden.csv`, `json/forbidden.json`, `logs/firewall.log`, `logs/plc.log` |
| `latency-direct/observe/enforce` | сравнение задержки без firewall, с firewall в observe и enforce | `csv/latency_*.csv`, `json/latency_compare.json`, `charts/latency_compare.svg` |
| `connection-loss-long-lived` | длительное TCP соединение, reset, timeout, reconnect | `csv/connection_loss.csv`, `json/connection_loss.json` |
| `hot reload` | применение новой policy без restart и с сохранением PID | `json/hot_reload.json`, `reports/hot_reload_report.md` |
| `recovery` | восстановление после принудительного завершения процесса | `json/recovery.json`, `logs/firewall_after_failure.log` |
| `stability` | длительная стабильность, CPU/RAM/threads, ошибки, reconnect | `csv/stability.csv`, `csv/resources.csv`, `json/stability.json`, `charts/resource_rss.png` |

## Итоговый отчёт

Главный Markdown-отчёт формируется автоматически:

```text
artifacts/operational-tests/reports/operational_test_report.md
```

Он содержит сводную таблицу для раздела ВКР «Испытания и оценка характеристик разработанного межсетевого экрана», включая:

- число обработанных запросов;
- разрешённые и заблокированные запросы;
- ошибки и потерянные соединения;
- среднюю задержку, медиану, p95 и p99;
- throughput;
- false positive;
- время hot reload;
- время восстановления;
- uptime и ресурсные показатели stability-прогона.
