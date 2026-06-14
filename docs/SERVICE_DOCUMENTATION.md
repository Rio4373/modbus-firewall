# Service Documentation: `modbus-firewall`

## 1. Назначение сервиса

`modbus-firewall` — это application-layer proxy для Modbus TCP, который встраивается между ARM/SCADA-клиентом и PLC.

Сервис решает три задачи:

1. Прозрачно проксировать Modbus TCP трафик к PLC.
2. Наблюдать и сохранять историю распознанных Modbus-операций в локальное хранилище.
3. Применять allowlist-политику к запросам без остановки процесса, с hot reload конфигурации и policy.

Сервис не является универсальным сетевым firewall. Он работает только на уровне Modbus TCP ADU/PDU и принимает решения по содержимому Modbus-запроса.

## 2. Границы ответственности

### Что сервис делает

- Принимает TCP-соединения от клиента.
- Разбирает Modbus TCP запросы.
- В `observe` режиме пропускает трафик и сохраняет нормализованные события.
- В `enforce` режиме проверяет запрос по `policy.yaml`.
- Передает разрешенные запросы в upstream PLC.
- Возвращает ответ PLC клиенту без модификации.
- При policy deny формирует локальный Modbus exception response.
- Периодически перечитывает `config.yaml` и `policy.yaml` без рестарта процесса.
- Генерирует candidate policy из ранее собранных событий.
- Выполняет offline replay исторических событий через текущую policy.

### Что сервис не делает

- Не хранит ответы PLC в базе.
- Не выполняет deep inspection прикладных значений регистров при принятии решения.
- Не поддерживает CIDR/подсети в policy, только точные IP.
- Не использует внешнюю БД, очередь, HTTP API, gRPC или сервис discovery.
- Не дает встроенного UI/API для управления policy.
- Не реализует аутентификацию, TLS/mTLS и rate limiting.

## 3. С какими сервисами и системами он взаимодействует

### Боевые и логические интеграции

| Контрагент | Протокол/канал | Направление | Зачем нужен |
|---|---|---|---|
| ARM / SCADA клиент | Modbus TCP | входящий | Источник запросов, которые сервис анализирует и проксирует |
| PLC / Modbus device | Modbus TCP | исходящий | Целевой upstream, куда уходят разрешенные запросы |
| SQLite | локальный файл `events.db` | локальный I/O | Хранение нормализованных событий Modbus |
| Файловая система | YAML/JSON/DB/JSON report | локальный I/O | Хранение `config.yaml`, policy-файлов, replay report и SQLite БД |
| Оператор / CI / shell | CLI | локальный запуск | Запуск proxy, генерации policy, replay и применения candidate policy |

### Компоненты стенда и демо

| Компонент | Роль | Примечание |
|---|---|---|
| `arm-sim` | Генератор тестового клиентского трафика | Входит в репозиторий, не обязателен для production |
| `plc-sim` | Симулятор PLC на PyModbus | Нужен для локального стенда и e2e/demo |
| Docker Compose стенд | Поднимает `arm-sim`, `firewall`, `plc-sim` | Нужен для воспроизводимого сценария |

Важно: `arm-sim` и `plc-sim` не являются внутренними модулями production-сервиса. Это вспомогательные компоненты для тестов, демонстрации и локальной проверки поведения firewall.

## 4. Основные сценарии работы

### `observe`

- Proxy принимает запрос от клиента.
- Сервис пытается распарсить Modbus ADU.
- Если парсинг успешен, запрос нормализуется в событие и сохраняется в SQLite.
- Запрос всегда передается в PLC.
- Ответ PLC без изменений возвращается клиенту.

Назначение режима:

- собрать реальный профиль обращений;
- накопить материал для policy generation;
- не ломать текущий трафик во время обучения.

### `enforce`

- Proxy принимает запрос от клиента.
- Сервис парсит Modbus ADU.
- При ошибке парсинга действует `safe deny`: запрос не передается в upstream.
- При успешном парсинге запрос проверяется по `policy.Matcher`.
- Если правило разрешает операцию, запрос идет в PLC.
- Если операция не покрыта policy, сервис возвращает локальный Modbus exception response и не обращается к PLC.

Назначение режима:

- пропускать только известные и явно разрешенные Modbus-операции;
- минимизировать риск нештатных write/read запросов.

### `generate-policy`

- Читает исторические события из SQLite.
- Группирует операции по:
  - `source_ip`
  - `destination_ip`
  - `unit_id`
  - `function_code`
- Для read-операций объединяет соседние и пересекающиеся диапазоны адресов.
- Для write-операций учитывает частоту и оставляет только диапазоны, которые встречались не реже порога `K`.
- Сохраняет результат в:
  - `policy.candidate.yaml`
  - `policy.generated.yaml`

### `replay`

- Загружает исторические события из SQLite.
- Прогоняет их через текущую policy.
- Строит report:
  - сколько событий покрыто;
  - сколько будет заблокировано;
  - какие операции остаются непокрытыми.

### `apply-policy`

- Валидирует candidate policy.
- Копирует ее в active policy атомарной заменой файла.
- При включенном hot reload новая policy подхватывается без рестарта процесса.

## 5. Архитектурные модули в коде

| Пакет | Ответственность |
|---|---|
| `cmd/firewall` | CLI команды сервиса |
| `internal/proxy` | TCP listener, proxy loop, observe/enforce, hot reload |
| `internal/modbus` | Парсер Modbus TCP запросов |
| `internal/policy` | YAML policy, matcher, validate/apply/reset |
| `internal/storage` | SQLite schema и доступ к событиям |
| `internal/generator` | Генерация allowlist policy из событий |
| `internal/replay` | Offline анализ покрытия policy |
| `internal/config` | Загрузка и валидация `config.yaml` |
| `internal/logging` | Инициализация `slog` |
| `cmd/arm-sim`, `internal/armsim` | Тестовый ARM-клиент |
| `plc-sim` | Тестовый PLC simulator на Python |

## 6. Поддерживаемые Modbus функции

### Что умеет firewall parser и matcher

- FC `01` Read Coils
- FC `02` Read Discrete Inputs
- FC `03` Read Holding Registers
- FC `04` Read Input Registers
- FC `05` Write Single Coil
- FC `06` Write Single Register
- FC `15` Write Multiple Coils
- FC `16` Write Multiple Registers

### Что реально поддерживает встроенный `plc-sim`

- FC `03`
- FC `04`
- FC `06`
- FC `16`

Это значит, что firewall на уровне кода умеет разбирать и фильтровать больше функций, чем поддерживает демонстрационный PLC simulator.

## 7. Какие сущности есть в сервисе

Ниже разделение на три класса: сущности, которые реально сохраняются; сущности-файлы; сущности только runtime.

### 7.1. Persisted entity в SQLite

Главная и единственная доменная запись, которая хранится в БД, — `ModbusEvent`.

Таблица: `modbus_events`

| Поле | Тип в БД | Смысл |
|---|---|---|
| `id` | `INTEGER PRIMARY KEY AUTOINCREMENT` | Идентификатор события |
| `timestamp` | `TEXT` | UTC timestamp в `RFC3339Nano` |
| `source_ip` | `TEXT` | IP клиента, отправившего запрос |
| `destination_ip` | `TEXT` | IP upstream PLC |
| `unit_id` | `INTEGER` | Modbus Unit ID |
| `function_code` | `INTEGER` | Код Modbus функции |
| `start_address` | `INTEGER` | Начальный адрес операции |
| `quantity` | `INTEGER` | Количество coils/registers в операции |
| `operation_type` | `TEXT` | `read`, `write` или `unknown` |

Индексы:

- `idx_modbus_events_timestamp`
- `idx_modbus_events_function_code`
- `idx_modbus_events_operation_type`

Что важно:

- Сохраняется только запрос, не ответ PLC.
- Значения записываемых регистров/coil в БД не сохраняются.
- Событие сохраняется и в `observe`, и в `enforce`, если запрос успешно распарсен.
- В `enforce` это включает и те запросы, которые затем будут заблокированы policy.

### 7.2. Persisted file-based сущности

#### `Config`

Файл: `configs/config.yaml`

Основные поля:

- `mode`
- `server.listen_addr`
- `proxy.upstream_addr`
- `proxy.dial_timeout`
- `proxy.read_timeout`
- `proxy.write_timeout`
- `logging.level`
- `logging.format`
- `storage.events_path`

#### `Policy`

Файлы:

- `configs/policy.yaml` — active policy
- `configs/policy.candidate.yaml` — candidate policy для правок/подготовки
- `configs/policy.generated.yaml` — baseline policy, сгенерированная автоматически

Структура policy:

- `version`
- `default_action`
- `rules[]`

Правило `Rule` содержит:

- `id`
- `action`
- `source_ips[]`
- `destination_ips[]`
- `unit_ids[]`
- `function_codes[]`
- `address_ranges[]`

`address_ranges[]` — это список диапазонов `[start, end]`, в которые запрос должен входить полностью.

#### `Replay report`

Файл по флагу `--output`, обычно `reports/replay-report.json`.

Хранит:

- `total_events`
- `covered_events`
- `blocked_events`
- `uncovered_operations[]`

### 7.3. Runtime-only сущности

Эти структуры есть в коде, но не хранятся как отдельные persisted записи:

| Сущность | Где используется | Хранится постоянно |
|---|---|---|
| `ParsedRequest` | после парсинга Modbus ADU | нет |
| `MatchRequest` | вход в policy matcher | нет |
| `Decision` | результат allow/deny | нет |
| `runtimeState` | текущий `mode` + `matcher` для hot reload | нет |
| `PolicyCandidate` | агрегированное представление для policy generation | нет |
| `Report` | результат replay | только если сериализован в JSON |
| `UncoveredOperation` | часть replay report | только если сериализована в JSON |

Отдельно важно:

- `PolicyCandidate` определен в storage-слое как агрегированная DTO-модель, но текущая реализация генератора policy читает сырые `ModbusEvent` и агрегирует их в памяти.
- Сервис не хранит отдельную таблицу правил, пользователей, сессий, инцидентов, конфигурационных версий или истории применений policy.

## 8. Как принимается решение по запросу

Матчинг policy работает по точному набору признаков:

1. `source_ip`
2. `destination_ip`
3. `unit_id`
4. `function_code`
5. Полное вхождение диапазона запроса в один из `address_ranges`

Поведение matcher:

- Правила просматриваются последовательно.
- Берется первое совпавшее правило.
- Если ни одно правило не совпало, возвращается `default_action`.
- Для MVP `default_action` обязан быть `deny`.

Важно:

- Диапазон запроса должен целиком помещаться в один policy-range.
- Поддерживаются только одиночные IP-адреса.
- Ошибка валидации `MatchRequest` интерпретируется как deny.

## 9. Жизненный цикл данных

### Online path

1. Клиент открывает TCP-соединение к firewall.
2. Firewall читает Modbus ADU.
3. `internal/modbus` извлекает `unit_id`, `function_code`, `start_address`, `quantity`.
4. `internal/proxy` сохраняет нормализованное событие в SQLite.
5. В `enforce` matcher решает `allow/deny`.
6. Разрешенный запрос уходит в PLC.
7. Ответ PLC возвращается клиенту.

### Offline path

1. Исторические события читаются из SQLite.
2. Генератор строит policy по observed access pattern.
3. Candidate policy валидируется и при необходимости редактируется.
4. Replay показывает покрытие policy на накопленных событиях.
5. Active policy заменяется атомарно.
6. Runtime proxy подхватывает новую policy через hot reload.

## 10. Поведение hot reload

Hot reload отслеживает два файла:

- `config.yaml`
- `policy.yaml`

Механика:

- Сервис запоминает `modtime + size` каждого файла.
- По таймеру перечитывает сигнатуры файлов.
- При изменении заново загружает config и, если нужен `enforce`, создает новый matcher.
- Новое состояние публикуется через atomic pointer.

Практический эффект:

- один и тот же TCP connection может начать жить в `observe`, а следующий запрос в нем уже будет обработан как `enforce`;
- policy может измениться без остановки listener и без разрыва существующих сокетов.

## 11. Артефакты, которые появляются в процессе работы

| Артефакт | Откуда появляется | Для чего нужен |
|---|---|---|
| `data/events.db` | `firewall run` | История observed/enforced запросов |
| `configs/policy.generated.yaml` | `generate-policy` | Базовая автогенерация без ручных правок |
| `configs/policy.candidate.yaml` | `generate-policy` | Рабочая версия для ревью и редактирования |
| `configs/policy.yaml` | `apply-policy` | Активная policy, которую читает runtime proxy |
| `reports/replay-report.json` | `replay --output` | Отчет покрытия и непокрытых операций |

## 12. Ограничения текущей реализации

- Single-process, single-node сервис с локальной SQLite.
- Нет репликации и shared state между инстансами.
- Нет partitioning трафика по tenant/site/asset.
- Нет отдельного API для policy management.
- Нет хранения payload values для write-команд.
- Генерация policy опирается на уже наблюдавшийся трафик и не понимает бизнес-контекст операций.
- `ListPolicyCandidates` есть в storage-слое, но не используется текущим генератором как основной путь.
- Встроенный `plc-sim` покрывает только часть Modbus функций, которые умеет firewall.

## 13. Что важно знать при внедрении

- Production-контур должен дать сервису стабильный upstream PLC адрес.
- В policy придется явно перечислять IP клиентов и PLC.
- Для `enforce` сначала нужен этап `observe`, иначе allowlist будет пустой или неполной.
- Перед включением `enforce` желательно прогонять `replay`, чтобы увидеть непокрытые операции.
- Если требуется несколько клиентов или несколько PLC, policy будет расти по комбинациям `source_ip` x `destination_ip` x `unit_id` x `function_code`.

## 14. Связанный документ

Высокоуровневая архитектура и sequence/data-flow представлены в [HLD](./HLD.md).
