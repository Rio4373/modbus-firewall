# PLC Simulator (PyModbus)

Минимальный Modbus TCP simulator для стенда:
- поддержка `holding registers` и `input registers`;
- поддержка FC `03`, `04`, `06`, `16`;
- инициализация регистров из JSON конфига;
- логирование read/write запросов.

## Структура
- `server.py` — запуск Modbus TCP сервера
- `config.json` — рабочий конфиг
- `config.example.json` — пример
- `requirements.txt` — Python зависимости

## Быстрый запуск
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r plc-sim/requirements.txt
python plc-sim/server.py --config plc-sim/config.json
```

## Параметры
- `--config` путь к JSON конфигу

## Формат config.json
```json
{
  "host": "0.0.0.0",
  "port": 502,
  "unit_id": 1,
  "register_count": 128,
  "log_level": "INFO",
  "holding_registers": {
    "0": 100,
    "1": 101
  },
  "input_registers": {
    "0": 900,
    "1": 901
  }
}
```

## Примечания
- Адреса регистров задаются в zero-based виде (`0`, `1`, `2`, ...).
- `unit_id` используется для контекста устройства; в стенде обычно `1`.
- В логах отображаются все операции чтения/записи по `hr` и `ir`.
