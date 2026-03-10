#!/usr/bin/env python3
import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from pymodbus.server import StartTcpServer
except Exception:
    from pymodbus.server.sync import StartTcpServer

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext

try:
    from pymodbus.datastore import ModbusDeviceContext as DeviceContext
except Exception:
    from pymodbus.datastore import ModbusSlaveContext as DeviceContext


class LoggingDataBlock(ModbusSequentialDataBlock):
    def __init__(self, name: str, address: int, values: List[int]) -> None:
        super().__init__(address, values)
        self.name = name

    def getValues(self, address: int, count: int = 1) -> List[int]:
        values = super().getValues(address, count)
        logging.info("READ block=%s address=%d count=%d values=%s", self.name, address, count, list(values))
        return values

    def setValues(self, address: int, values) -> None:
        if isinstance(values, (tuple, list)):
            normalized = list(values)
        else:
            normalized = [int(values)]

        logging.info("WRITE block=%s address=%d count=%d values=%s", self.name, address, len(normalized), normalized)
        super().setValues(address, normalized)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Простой PLC simulator на PyModbus")
    parser.add_argument("--config", default="plc-sim/config.json", help="Путь к JSON конфигу")
    return parser.parse_args()


def load_config(path: Path) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"конфиг не найден: {path}")

    raw = path.read_text(encoding="utf-8")
    cfg = json.loads(raw)

    required = ["host", "port", "unit_id", "register_count", "holding_registers", "input_registers", "log_level"]
    for key in required:
        if key not in cfg:
            raise ValueError(f"в конфиге отсутствует обязательное поле: {key}")

    return cfg


def validate_config(cfg: Dict) -> None:
    if not isinstance(cfg["host"], str) or not cfg["host"].strip():
        raise ValueError("host должен быть непустой строкой")

    port = int(cfg["port"])
    if port < 1 or port > 65535:
        raise ValueError("port должен быть в диапазоне 1..65535")

    unit_id = int(cfg["unit_id"])
    if unit_id < 1 or unit_id > 255:
        raise ValueError("unit_id должен быть в диапазоне 1..255")

    register_count = int(cfg["register_count"])
    if register_count <= 0:
        raise ValueError("register_count должен быть > 0")

    validate_register_map(cfg["holding_registers"], register_count, "holding_registers")
    validate_register_map(cfg["input_registers"], register_count, "input_registers")


def validate_register_map(values: Dict, register_count: int, field_name: str) -> None:
    if not isinstance(values, dict):
        raise ValueError(f"{field_name} должен быть объектом map")

    for key, value in values.items():
        address = int(key)
        if address < 0 or address >= register_count:
            raise ValueError(f"{field_name}[{key}]: адрес вне диапазона 0..{register_count - 1}")

        register_value = int(value)
        if register_value < 0 or register_value > 0xFFFF:
            raise ValueError(f"{field_name}[{key}]: значение вне диапазона 0..65535")


def build_block(register_count: int, register_values: Dict, name: str) -> LoggingDataBlock:
    values = [0] * register_count
    for key, value in register_values.items():
        values[int(key)] = int(value)

    return LoggingDataBlock(name=name, address=0, values=values)


def build_context(cfg: Dict) -> Tuple[ModbusServerContext, int]:
    register_count = int(cfg["register_count"])
    unit_id = int(cfg["unit_id"])

    holding = build_block(register_count, cfg["holding_registers"], "holding")
    input_regs = build_block(register_count, cfg["input_registers"], "input")

    store = DeviceContext(
        di=ModbusSequentialDataBlock(0, [0] * register_count),
        co=ModbusSequentialDataBlock(0, [0] * register_count),
        hr=holding,
        ir=input_regs,
    )

    try:
        context = ModbusServerContext(devices={unit_id: store}, single=False)
    except TypeError:
        context = ModbusServerContext(slaves={unit_id: store}, single=False)

    return context, register_count


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def main() -> None:
    args = parse_args()
    config_path = Path(args.config)

    cfg = load_config(config_path)
    validate_config(cfg)
    configure_logging(cfg["log_level"])

    context, register_count = build_context(cfg)

    host = cfg["host"].strip()
    port = int(cfg["port"])
    unit_id = int(cfg["unit_id"])

    logging.info("PLC simulator запущен")
    logging.info("listen=%s:%d unit_id=%d register_count=%d", host, port, unit_id, register_count)
    logging.info("FC03/FC04/FC06/FC16 поддерживаются через datastore hr/ir")

    StartTcpServer(context=context, address=(host, port))


if __name__ == "__main__":
    main()
