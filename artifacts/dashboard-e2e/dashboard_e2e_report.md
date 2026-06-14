# Dashboard E2E отчет

Дата запуска: 2026-06-11T20:06:57+00:00

Итог: 2/3 проверок пройдено.

| Проверка | Статус | Детали |
|---|---:|---|
| История событий очищена с backup предыдущей БД | PASS | `['/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/dashboard-e2e/backups/20260611T200657Z/events.db']` |
| API доступен и firewall online | PASS | `{'active_connections': 0, 'active_policy': 'policy.yaml', 'active_policy_id': 'active', 'connection_losses': 0, 'last_policy_apply_time': '2026-06-11T20:04:36.087235166Z', 'mode': ` |
| E2E остановлен из-за ошибки | FAIL | `dashboard root markup not found` |

## Ключевые показатели

| Показатель | Значение |
|---|---:|
| Режим после теста | ANALYZE |
| PID firewall | 1 |
| Правил active policy | 3 |
| Обработано запросов | 0 |
| Разрешено запросов | 0 |
| Заблокировано запросов | 0 |
| Ошибки обработки | 0 |
| Потери соединений | 0 |
| Средняя задержка, мс | 0 |
| p95, мс | 0 |
| p99, мс | 0 |

Артефакты: `dashboard_e2e_results.json`, `dashboard_e2e_report.md`.
