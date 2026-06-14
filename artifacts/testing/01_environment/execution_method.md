# Способ воспроизведения

Для подготовки артефактов использован локальный изолированный стенд внутри репозитория:

- firewall: [/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/firewall](./runtime/bin/firewall)
- arm-sim: [/Users/maratbagautdinov/Desktop/modbus-firewall/artifacts/testing/01_environment/runtime/bin/arm-sim](./runtime/bin/arm-sim)
- plc-sim: исходный файл [plc-sim/server.py](../../plc-sim/server.py)
- конфигурация стенда: [runtime_config_initial.yaml](./runtime_config_initial.yaml)
- SQLite: [runtime/events.db](./runtime/events.db)

Выбран локальный путь, а не Docker Compose, чтобы:

- фиксировать один и тот же PID процесса firewall до и после hot reload;
- собирать отдельные срезы логов по каждому сценарию;
- не изменять рабочие файлы `configs/` и `data/` в корне репозитория.
