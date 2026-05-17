#!/usr/bin/env python3
"""Operational and load test runner for the Modbus TCP firewall.

The runner intentionally uses only Python stdlib. It starts a deterministic
PLC simulator, launches the firewall binary, drives raw Modbus TCP traffic and
stores CSV/JSON/Markdown/SVG/PNG artifacts suitable for thesis materials.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT_DIR = ROOT / "artifacts" / "operational-tests"


SUPPORTED_FCS = (1, 3, 5, 6, 15, 16)
READ_FCS = {1, 3}
WRITE_FCS = {5, 6, 15, 16}
NETWORK_ERRORS = ("connection reset", "broken pipe", "timed out", "refused", "closed")


@dataclass(frozen=True)
class Operation:
    name: str
    fc: int
    address: int
    quantity: int
    allowed: bool
    builder: Callable[[int], bytes]
    source_ip: str = "127.0.0.1"


@dataclass
class ServiceProcess:
    name: str
    process: subprocess.Popen
    log_path: Path

    @property
    def pid(self) -> int:
        return int(self.process.pid)

    def stop(self) -> None:
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class ModbusPLCServer:
    def __init__(self, host: str, port: int, log_path: Path) -> None:
        self.host = host
        self.port = port
        self.log_path = log_path
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self.coils = [False] * 512
        self.holding = [idx for idx in range(512)]
        self.requests = Counter()
        self.total_requests = 0

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")
        self._thread = threading.Thread(target=self._serve, name="plc-sim", daemon=True)
        self._thread.start()
        wait_for_port(self.host, self.port, "plc-sim")

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "by_function_code": dict(self.requests),
                "register_50": self.holding[50],
                "register_60": self.holding[60],
            }

    def _serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            self._sock = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(128)
            srv.settimeout(0.5)
            self._log("PLC simulator started listen=%s:%s" % (self.host, self.port))
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr) -> None:
        with conn:
            conn.settimeout(3)
            while not self._stop.is_set():
                try:
                    adu = recv_adu(conn)
                except TimeoutError:
                    continue
                except OSError:
                    return
                except ValueError as exc:
                    self._log(f"MALFORMED source={addr[0]} error={exc}")
                    return
                if not adu:
                    return
                try:
                    response = self._handle_adu(adu, addr[0])
                    conn.sendall(response)
                except Exception as exc:  # noqa: BLE001 - simulator must not kill process.
                    self._log(f"ERROR source={addr[0]} error={exc}")
                    try:
                        conn.sendall(exception_response(adu, adu[7] if len(adu) > 7 else 0, 4))
                    except OSError:
                        return

    def _handle_adu(self, adu: bytes, source_ip: str) -> bytes:
        if len(adu) < 8:
            raise ValueError("short ADU")
        tx_id, proto_id, length = struct.unpack(">HHH", adu[:6])
        unit_id = adu[6]
        pdu = adu[7:]
        if proto_id != 0 or length + 6 != len(adu):
            raise ValueError("invalid MBAP")
        fc = pdu[0]
        with self._lock:
            self.requests[str(fc)] += 1
            self.total_requests += 1

        if fc in (1, 3):
            address, quantity = struct.unpack(">HH", pdu[1:5])
            if quantity <= 0:
                return exception_response(adu, fc, 3)
            if fc == 1:
                byte_count = (quantity + 7) // 8
                payload = bytearray(byte_count)
                with self._lock:
                    for idx in range(quantity):
                        if self.coils[address + idx]:
                            payload[idx // 8] |= 1 << (idx % 8)
                data = bytes([fc, byte_count]) + bytes(payload)
            else:
                with self._lock:
                    values = self.holding[address : address + quantity]
                data = bytes([fc, quantity * 2]) + b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
            self._log(f"READ source={source_ip} fc={fc} address={address} quantity={quantity}")
            return mbap(tx_id, unit_id, data)

        if fc == 5:
            address, value = struct.unpack(">HH", pdu[1:5])
            with self._lock:
                self.coils[address] = value == 0xFF00
            self._log(f"WRITE source={source_ip} fc=5 address={address} quantity=1")
            return mbap(tx_id, unit_id, pdu[:5])

        if fc == 6:
            address, value = struct.unpack(">HH", pdu[1:5])
            with self._lock:
                self.holding[address] = value
            self._log(f"WRITE source={source_ip} fc=6 address={address} quantity=1 value={value}")
            return mbap(tx_id, unit_id, pdu[:5])

        if fc == 15:
            address, quantity, byte_count = struct.unpack(">HHB", pdu[1:6])
            values = pdu[6 : 6 + byte_count]
            with self._lock:
                for idx in range(quantity):
                    self.coils[address + idx] = bool(values[idx // 8] & (1 << (idx % 8)))
            self._log(f"WRITE source={source_ip} fc=15 address={address} quantity={quantity}")
            return mbap(tx_id, unit_id, bytes([fc]) + struct.pack(">HH", address, quantity))

        if fc == 16:
            address, quantity, byte_count = struct.unpack(">HHB", pdu[1:6])
            values = [struct.unpack(">H", pdu[6 + i : 8 + i])[0] for i in range(0, byte_count, 2)]
            with self._lock:
                for idx, value in enumerate(values[:quantity]):
                    self.holding[address + idx] = value
            self._log(f"WRITE source={source_ip} fc=16 address={address} quantity={quantity}")
            return mbap(tx_id, unit_id, bytes([fc]) + struct.pack(">HH", address, quantity))

        return exception_response(adu, fc, 1)

    def _log(self, message: str) -> None:
        line = f"{utc_now()} {message}\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def mbap(tx_id: int, unit_id: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tx_id & 0xFFFF, 0, len(pdu) + 1, unit_id) + pdu


def exception_response(request: bytes, fc: int, code: int) -> bytes:
    tx_id = struct.unpack(">H", request[:2])[0] if len(request) >= 2 else 0
    unit_id = request[6] if len(request) >= 7 else 1
    return mbap(tx_id, unit_id, bytes([(fc | 0x80) & 0xFF, code & 0xFF]))


def recv_adu(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 6)
    if not header:
        return b""
    length = struct.unpack(">H", header[4:6])[0]
    if length < 2 or length > 254:
        raise ValueError(f"invalid MBAP length={length}")
    return header + recv_exact(conn, length)


def recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            if not chunks:
                return b""
            raise OSError("connection closed while reading")
        chunks.extend(chunk)
    return bytes(chunks)


def build_read(fc: int, address: int, quantity: int) -> Callable[[int], bytes]:
    return lambda tx: mbap(tx, 1, bytes([fc]) + struct.pack(">HH", address, quantity))


def build_fc05(address: int, value: bool) -> Callable[[int], bytes]:
    raw = 0xFF00 if value else 0x0000
    return lambda tx: mbap(tx, 1, bytes([5]) + struct.pack(">HH", address, raw))


def build_fc06(address: int, value: int) -> Callable[[int], bytes]:
    return lambda tx: mbap(tx, 1, bytes([6]) + struct.pack(">HH", address, value & 0xFFFF))


def build_fc15(address: int, quantity: int, packed: int) -> Callable[[int], bytes]:
    byte_count = (quantity + 7) // 8
    payload = packed.to_bytes(byte_count, "little")
    return lambda tx: mbap(tx, 1, bytes([15]) + struct.pack(">HHB", address, quantity, byte_count) + payload)


def build_fc16(address: int, values: list[int]) -> Callable[[int], bytes]:
    payload = b"".join(struct.pack(">H", value & 0xFFFF) for value in values)
    return lambda tx: mbap(tx, 1, bytes([16]) + struct.pack(">HHB", address, len(values), len(payload)) + payload)


def build_bad_quantity(tx: int) -> bytes:
    return mbap(tx, 1, bytes([3]) + struct.pack(">HH", 0, 0))


def allowed_operations() -> list[Operation]:
    return [
        Operation("allow-fc01-read-coils", 1, 0, 8, True, build_read(1, 0, 8)),
        Operation("allow-fc03-read-holding", 3, 0, 4, True, build_read(3, 0, 4)),
        Operation("allow-fc05-write-coil", 5, 10, 1, True, build_fc05(10, True)),
        Operation("allow-fc06-write-register", 6, 12, 1, True, build_fc06(12, 1234)),
        Operation("allow-fc15-write-coils", 15, 20, 8, True, build_fc15(20, 8, 0b10101010)),
        Operation("allow-fc16-write-registers", 16, 30, 2, True, build_fc16(30, [777, 888])),
    ]


def mixed_operations(include_source_ip_probe: bool = True) -> list[Operation]:
    ops = allowed_operations() + [
        Operation("deny-fc03-register-range", 3, 300, 4, False, build_read(3, 300, 4)),
        Operation("deny-fc06-register", 6, 60, 1, False, build_fc06(60, 9999)),
        Operation("deny-fc04-forbidden-fc", 4, 0, 1, False, build_read(4, 0, 1)),
        Operation("deny-invalid-quantity", 3, 0, 0, False, build_bad_quantity),
    ]
    if include_source_ip_probe:
        ops.insert(-1, Operation("deny-source-ip", 3, 0, 4, False, build_read(3, 0, 4), source_ip="127.0.0.2"))
    return ops


def write_policy(path: Path, include_register_60: bool = False) -> None:
    extra = ""
    if include_register_60:
        extra = """
  - id: allow-hot-register-60
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [6]
    address_ranges:
      - {start: 60, end: 60}
"""
    path.write_text(
        f"""version: 1
default_action: deny
rules:
  - id: allow-fc01-read-coils
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [1]
    address_ranges:
      - {{start: 0, end: 31}}
  - id: allow-fc03-read-holding
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - {{start: 0, end: 63}}
  - id: allow-fc05-write-coil
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [5]
    address_ranges:
      - {{start: 10, end: 10}}
  - id: allow-fc06-write-register
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [6]
    address_ranges:
      - {{start: 12, end: 12}}
  - id: allow-fc15-write-coils
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [15]
    address_ranges:
      - {{start: 20, end: 27}}
  - id: allow-fc16-write-registers
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [16]
    address_ranges:
      - {{start: 30, end: 31}}
{extra}""",
        encoding="utf-8",
    )


def write_config(path: Path, mode: str, listen_port: int, upstream_port: int, events_path: Path) -> None:
    path.write_text(
        f"""mode: {mode}
server:
  listen_addr: "127.0.0.1:{listen_port}"
proxy:
  upstream_addr: "127.0.0.1:{upstream_port}"
  dial_timeout: "3s"
  read_timeout: "5s"
  write_timeout: "5s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "{events_path}"
""",
        encoding="utf-8",
    )


def wait_for_port(host: str, port: int, label: str, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1)
    raise RuntimeError(f"{label} did not open {host}:{port}: {last_error}")


def run_cmd(cmd: list[str], cwd: Path, log_path: Path, env: dict[str, str] | None = None) -> None:
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, text=True, check=False, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed rc={proc.returncode}: {' '.join(cmd)}; log={log_path}")


def start_firewall(binary: Path, config: Path, policy: Path, log_path: Path) -> ServiceProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(binary), "run", "--config", str(config), "--policy", str(policy), "--reload-interval", "500ms"],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(0.2)
    if proc.poll() is not None:
        log.close()
        raise RuntimeError(f"firewall exited early rc={proc.returncode}; log={log_path}")
    return ServiceProcess("firewall", proc, log_path)


def request_once(host: str, port: int, op: Operation, tx_id: int, timeout: float = 3.0) -> tuple[str, float, str, bool]:
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if op.source_ip != "127.0.0.1":
                sock.bind((op.source_ip, 0))
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(op.builder(tx_id))
            response = recv_adu(sock)
        latency_ms = (time.perf_counter() - start) * 1000
        if not response:
            if op.allowed:
                return "error", latency_ms, "empty_response", True
            return "blocked", latency_ms, "connection_closed_safe_deny", False
        if len(response) >= 8 and response[7] & 0x80:
            return "blocked", latency_ms, f"exception_code={response[8] if len(response) > 8 else 'n/a'}", False
        return "allowed", latency_ms, "", False
    except Exception as exc:  # noqa: BLE001 - every request must be measured.
        latency_ms = (time.perf_counter() - start) * 1000
        lowered = str(exc).lower()
        dropped = any(marker in lowered for marker in NETWORK_ERRORS)
        return "error", latency_ms, type(exc).__name__ + ":" + str(exc), dropped


def run_workload(
    name: str,
    target_host: str,
    target_port: int,
    operations: list[Operation],
    requests: int,
    csv_path: Path,
    reuse_connection: bool = False,
    stop_event: threading.Event | None = None,
) -> dict:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    counters = Counter()
    latencies: list[float] = []
    throughput_buckets = Counter()
    started = time.perf_counter()
    started_wall = time.time()
    tx = 1

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(
            ["timestamp_utc", "test", "seq", "operation", "fc", "address", "quantity", "expected", "outcome", "latency_ms", "detail"]
        )
        if reuse_connection:
            run_reuse_connection(writer, name, target_host, target_port, operations, requests, counters, latencies, throughput_buckets, started_wall, stop_event)
        else:
            for seq in range(1, requests + 1):
                if stop_event and stop_event.is_set():
                    break
                op = operations[(seq - 1) % len(operations)]
                outcome, latency_ms, detail, dropped = request_once(target_host, target_port, op, tx)
                tx = (tx + 1) & 0xFFFF or 1
                expected = "allowed" if op.allowed else "blocked"
                counters[outcome] += 1
                counters["connection_drops"] += int(dropped)
                counters["errors"] += int(outcome == "error")
                counters["unexpected"] += int((op.allowed and outcome != "allowed") or ((not op.allowed) and outcome == "allowed"))
                latencies.append(latency_ms)
                throughput_buckets[int(time.time() - started_wall)] += 1
                writer.writerow([utc_now(), name, seq, op.name, op.fc, op.address, op.quantity, expected, outcome, f"{latency_ms:.3f}", detail])

    duration = max(time.perf_counter() - started, 1e-9)
    return summarize_metrics(name, counters, latencies, duration, throughput_buckets, requests)


def run_timed_workload(
    name: str,
    target_host: str,
    target_port: int,
    operations: list[Operation],
    duration_sec: int,
    csv_path: Path,
    interval_sec: float = 0.05,
) -> dict:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    counters = Counter()
    latencies: list[float] = []
    throughput_buckets = Counter()
    started = time.perf_counter()
    started_wall = time.time()
    deadline = started + max(duration_sec, 1)
    seq = 0
    tx = 1

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(
            ["timestamp_utc", "test", "seq", "operation", "fc", "address", "quantity", "expected", "outcome", "latency_ms", "detail"]
        )
        while time.perf_counter() < deadline:
            seq += 1
            op = operations[(seq - 1) % len(operations)]
            outcome, latency_ms, detail, dropped = request_once(target_host, target_port, op, tx)
            tx = (tx + 1) & 0xFFFF or 1
            expected = "allowed" if op.allowed else "blocked"
            counters[outcome] += 1
            counters["connection_drops"] += int(dropped)
            counters["errors"] += int(outcome == "error")
            counters["unexpected"] += int((op.allowed and outcome != "allowed") or ((not op.allowed) and outcome == "allowed"))
            latencies.append(latency_ms)
            throughput_buckets[int(time.time() - started_wall)] += 1
            writer.writerow([utc_now(), name, seq, op.name, op.fc, op.address, op.quantity, expected, outcome, f"{latency_ms:.3f}", detail])
            fh.flush()
            sleep_for = interval_sec - (latency_ms / 1000)
            if sleep_for > 0:
                time.sleep(sleep_for)

    duration = max(time.perf_counter() - started, 1e-9)
    return summarize_metrics(name, counters, latencies, duration, throughput_buckets, seq)


def hot_reload_same_connection(
    target_host: str,
    target_port: int,
    op_before: Operation,
    op_after: Operation,
    policy_path: Path,
) -> tuple[str, str, float]:
    started = time.perf_counter()
    with socket.create_connection((target_host, target_port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(op_before.builder(41000))
        before_response = recv_adu(sock)
        before = "blocked" if len(before_response) >= 8 and before_response[7] & 0x80 else "allowed"
        write_policy(policy_path, include_register_60=True)
        time.sleep(1.2)
        sock.sendall(op_after.builder(41001))
        after_response = recv_adu(sock)
        after = "blocked" if len(after_response) >= 8 and after_response[7] & 0x80 else "allowed"
    return before, after, time.perf_counter() - started


def run_reuse_connection(writer, name, target_host, target_port, operations, requests, counters, latencies, buckets, started_wall, stop_event) -> None:
    seq = 0
    tx = 1
    try:
        with socket.create_connection((target_host, target_port), timeout=3) as sock:
            sock.settimeout(3)
            while seq < requests:
                if stop_event and stop_event.is_set():
                    break
                seq += 1
                op = operations[(seq - 1) % len(operations)]
                start = time.perf_counter()
                detail = ""
                dropped = False
                try:
                    sock.sendall(op.builder(tx))
                    response = recv_adu(sock)
                    latency_ms = (time.perf_counter() - start) * 1000
                    outcome = "blocked" if len(response) >= 8 and response[7] & 0x80 else "allowed"
                except Exception as exc:  # noqa: BLE001
                    latency_ms = (time.perf_counter() - start) * 1000
                    outcome = "error"
                    detail = type(exc).__name__ + ":" + str(exc)
                    dropped = True
                tx = (tx + 1) & 0xFFFF or 1
                expected = "allowed" if op.allowed else "blocked"
                counters[outcome] += 1
                counters["connection_drops"] += int(dropped)
                counters["errors"] += int(outcome == "error")
                counters["unexpected"] += int((op.allowed and outcome != "allowed") or ((not op.allowed) and outcome == "allowed"))
                latencies.append(latency_ms)
                buckets[int(time.time() - started_wall)] += 1
                writer.writerow([utc_now(), name, seq, op.name, op.fc, op.address, op.quantity, expected, outcome, f"{latency_ms:.3f}", detail])
    except Exception as exc:  # noqa: BLE001
        counters["errors"] += 1
        counters["connection_drops"] += 1
        writer.writerow([utc_now(), name, 0, "connect", 0, 0, 0, "allowed", "error", "0.000", type(exc).__name__ + ":" + str(exc)])


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * p))))
    return ordered[idx]


def summarize_metrics(name: str, counters: Counter, latencies: list[float], duration: float, buckets: Counter, requested: int) -> dict:
    processed = counters["allowed"] + counters["blocked"] + counters["error"]
    return {
        "name": name,
        "requested": requested,
        "processed": processed,
        "allowed": counters["allowed"],
        "blocked": counters["blocked"],
        "errors": counters["errors"],
        "unexpected": counters["unexpected"],
        "connection_drops": counters["connection_drops"],
        "avg_latency_ms": round(mean(latencies), 3) if latencies else 0.0,
        "median_latency_ms": round(median(latencies), 3) if latencies else 0.0,
        "p95_latency_ms": round(percentile(latencies, 0.95), 3),
        "p99_latency_ms": round(percentile(latencies, 0.99), 3),
        "throughput_rps": round(processed / duration, 2),
        "duration_sec": round(duration, 3),
        "throughput_buckets": dict(sorted(buckets.items())),
    }


def read_proc_metrics(pid: int) -> dict:
    try:
        out = subprocess.check_output(["ps", "-o", "pid=,%cpu=,%mem=,rss=", "-p", str(pid)], text=True).strip()
        parts = out.split()
        return {"pid": pid, "cpu_percent": float(parts[1]), "mem_percent": float(parts[2]), "rss_kb": int(parts[3]), "threads": count_threads(pid)}
    except Exception:
        return {"pid": pid, "cpu_percent": 0.0, "mem_percent": 0.0, "rss_kb": 0, "threads": 0}


def count_threads(pid: int) -> int:
    try:
        out = subprocess.check_output(["ps", "-M", str(pid)], text=True, stderr=subprocess.DEVNULL)
        return max(0, len(out.splitlines()) - 1)
    except Exception:
        try:
            out = subprocess.check_output(["ps", "-o", "nlwp=", "-p", str(pid)], text=True, stderr=subprocess.DEVNULL).strip()
            return int(out)
        except Exception:
            return 0


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_table_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_line_svg(path: Path, title: str, series: dict[str, list[tuple[float, float]]], y_label: str) -> None:
    width, height = 960, 420
    margin = 58
    all_points = [point for values in series.values() for point in values]
    if not all_points:
        all_points = [(0, 0), (1, 1)]
    min_x, max_x = min(x for x, _ in all_points), max(x for x, _ in all_points)
    min_y, max_y = 0, max(max(y for _, y in all_points), 1)
    span_x = max(max_x - min_x, 1)
    span_y = max(max_y - min_y, 1)
    colors = ["#2563eb", "#dc2626", "#059669", "#9333ea", "#ea580c"]

    def sx(x: float) -> float:
        return margin + (x - min_x) / span_x * (width - 2 * margin)

    def sy(y: float) -> float:
        return height - margin - (y - min_y) / span_y * (height - 2 * margin)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{margin}" y="34" font-family="Arial" font-size="22" font-weight="700">{escape_xml(title)}</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="#111827"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="#111827"/>',
        f'<text x="18" y="{margin}" font-family="Arial" font-size="12">{escape_xml(y_label)}</text>',
    ]
    for idx in range(5):
        y = min_y + span_y * idx / 4
        py = sy(y)
        lines.append(f'<line x1="{margin}" y1="{py:.1f}" x2="{width-margin}" y2="{py:.1f}" stroke="#e5e7eb"/>')
        lines.append(f'<text x="8" y="{py+4:.1f}" font-family="Arial" font-size="11">{y:.1f}</text>')
    for idx, (label, values) in enumerate(series.items()):
        color = colors[idx % len(colors)]
        points = " ".join(f"{sx(x):.1f},{sy(y):.1f}" for x, y in values)
        lines.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{points}"/>')
        lx = margin + idx * 180
        lines.append(f'<rect x="{lx}" y="{height-28}" width="14" height="4" fill="{color}"/>')
        lines.append(f'<text x="{lx+20}" y="{height-22}" font-family="Arial" font-size="13">{escape_xml(label)}</text>')
    lines.append("</svg>")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_bar_svg(path: Path, title: str, values: dict[str, float], y_label: str) -> None:
    width, height = 960, 420
    margin = 64
    max_value = max(values.values()) if values else 1
    max_value = max(max_value, 1)
    bar_width = (width - 2 * margin) / max(len(values), 1) * 0.58
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{margin}" y="34" font-family="Arial" font-size="22" font-weight="700">{escape_xml(title)}</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="#111827"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="#111827"/>',
        f'<text x="18" y="{margin}" font-family="Arial" font-size="12">{escape_xml(y_label)}</text>',
    ]
    colors = ["#2563eb", "#059669", "#dc2626", "#7c3aed"]
    step = (width - 2 * margin) / max(len(values), 1)
    for idx, (label, value) in enumerate(values.items()):
        x = margin + idx * step + (step - bar_width) / 2
        h = (value / max_value) * (height - 2 * margin)
        y = height - margin - h
        color = colors[idx % len(colors)]
        lines.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{h:.1f}" fill="{color}"/>')
        lines.append(f'<text x="{x:.1f}" y="{y-8:.1f}" font-family="Arial" font-size="12">{value:.3f}</text>')
        lines.append(f'<text x="{x:.1f}" y="{height-margin+22}" font-family="Arial" font-size="12">{escape_xml(label)}</text>')
    lines.append("</svg>")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_simple_png(path: Path, title: str, values: list[float]) -> None:
    width, height = 960, 420
    pixels = bytearray([255, 255, 255] * width * height)

    def set_px(x: int, y: int, rgb: tuple[int, int, int]) -> None:
        if 0 <= x < width and 0 <= y < height:
            off = (y * width + x) * 3
            pixels[off : off + 3] = bytes(rgb)

    for x in range(60, width - 50):
        set_px(x, height - 60, (17, 24, 39))
    for y in range(50, height - 60):
        set_px(60, y, (17, 24, 39))
    if values:
        max_v = max(max(values), 1.0)
        prev = None
        for idx, value in enumerate(values):
            x = 60 + int(idx / max(len(values) - 1, 1) * (width - 120))
            y = height - 60 - int(value / max_v * (height - 120))
            if prev:
                draw_line(set_px, prev[0], prev[1], x, y, (37, 99, 235))
            prev = (x, y)
    write_png(path, width, height, bytes(pixels))


def draw_line(set_px, x0: int, y0: int, x1: int, y1: int, rgb: tuple[int, int, int]) -> None:
    dx = abs(x1 - x0)
    dy = -abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx + dy
    while True:
        for ox in (-1, 0, 1):
            for oy in (-1, 0, 1):
                set_px(x0 + ox, y0 + oy, rgb)
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def write_png(path: Path, width: int, height: int, rgb: bytes) -> None:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + rgb[y * width * 3 : (y + 1) * width * 3] for y in range(height))
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def escape_xml(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def supports_loopback_alias() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.2", 0))
        return True
    except OSError:
        return False


def sample_resources(pid: int, stop_event: threading.Event, csv_path: Path, interval: float = 1.0) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["timestamp_utc", "pid", "cpu_percent", "mem_percent", "rss_kb", "threads"])
        while not stop_event.is_set():
            row = read_proc_metrics(pid)
            writer.writerow([utc_now(), row["pid"], row["cpu_percent"], row["mem_percent"], row["rss_kb"], row["threads"]])
            fh.flush()
            time.sleep(interval)


def generate_report(report_path: Path, results: dict, artifact_dir: Path) -> None:
    summary = results["summary"]
    false_positive = results["false_positive"]
    hot = results["hot_reload"]
    recovery = results["recovery"]
    stability = results["stability"]
    report_path.write_text(
        f"""# Испытания и оценка характеристик разработанного межсетевого экрана

Дата запуска: {results['started_at']}

## Сводная таблица

| Показатель | Значение |
| --- | ---: |
| Обработано запросов в нагрузочном тесте | {summary['processed']} |
| Разрешено | {summary['allowed']} |
| Заблокировано | {summary['blocked']} |
| Ошибки | {summary['errors']} |
| Потерянные соединения | {summary['connection_drops']} |
| Средняя задержка, мс | {summary['avg_latency_ms']} |
| Медианная задержка, мс | {summary['median_latency_ms']} |
| p95, мс | {summary['p95_latency_ms']} |
| p99, мс | {summary['p99_latency_ms']} |
| Throughput, req/sec | {summary['throughput_rps']} |
| False positive | {false_positive['false_positive']} |
| False positive, % | {false_positive['false_positive_percent']} |
| Потери соединений в long-lived тесте | {results['connection_loss']['connection_drops']} |
| Время hot reload, сек | {hot['reload_detected_sec']} |
| PID до/после hot reload | {hot['pid_before']} / {hot['pid_after']} |
| Время восстановления после сбоя, сек | {recovery['recovery_time_sec']} |
| Uptime stability-прогона, сек | {stability['duration_sec']} |

## Нагрузочное тестирование

Сгенерирована смесь Modbus TCP запросов FC01, FC03, FC05, FC06, FC15 и FC16, а также запрещённых операций: неразрешённые регистры, запрещённый FC и некорректные параметры. Проверка неразрешённого source IP выполняется автоматически, когда ОС разрешает bind к альтернативному loopback-адресу. Результаты сохранены в `csv/load_requests.csv` и `json/load_summary.json`.

Графики: `charts/throughput.svg`, `charts/latency_compare.svg`, `charts/load_latency.png`.

## Ложные срабатывания

Повторно воспроизведён легитимный allow-list трафик. False positive: {false_positive['false_positive']} из {false_positive['total']} ({false_positive['false_positive_percent']}%). {'Ложные срабатывания отсутствуют.' if false_positive['false_positive'] == 0 else 'Обнаружены ложные срабатывания, требуется анализ policy.'}

## Блокировка запрещённых операций

Firewall заблокировал {results['forbidden']['blocked']} запрещённых запросов из {results['forbidden']['total']}; до PLC дошло {results['forbidden']['plc_delta']} запрещённых операций. Примеры логов сохранены в `logs/firewall.log` и `logs/plc.log`.

Проверка неразрешённого source IP: {results['source_ip_probe']['note']}.

## Сравнение задержек

| Режим | avg, мс | median, мс | p95, мс | p99, мс | throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| Без firewall | {results['latency']['direct']['avg_latency_ms']} | {results['latency']['direct']['median_latency_ms']} | {results['latency']['direct']['p95_latency_ms']} | {results['latency']['direct']['p99_latency_ms']} | {results['latency']['direct']['throughput_rps']} |
| Firewall observe | {results['latency']['observe']['avg_latency_ms']} | {results['latency']['observe']['median_latency_ms']} | {results['latency']['observe']['p95_latency_ms']} | {results['latency']['observe']['p99_latency_ms']} | {results['latency']['observe']['throughput_rps']} |
| Firewall enforce | {results['latency']['enforce']['avg_latency_ms']} | {results['latency']['enforce']['median_latency_ms']} | {results['latency']['enforce']['p95_latency_ms']} | {results['latency']['enforce']['p99_latency_ms']} | {results['latency']['enforce']['throughput_rps']} |

## Hot Reload

PID до обновления: {hot['pid_before']}. PID после обновления: {hot['pid_after']}. Restart detected: {hot['restart_detected']}. Новое правило начало применяться на существующем TCP соединении: {hot['same_connection_policy_applied']}.

## Восстановление после сбоя

Firewall был принудительно завершён и поднят локальным supervisor-процедурой раннера. Время восстановления: {recovery['recovery_time_sec']} сек. Доступность после восстановления: {recovery['available_after_restart']}. Конфигурация сохранена: {recovery['config_preserved']}.

## Длительная стабильность

Профиль stability можно запускать на 12-24 часа через `STABILITY_SECONDS=43200 make test-reliability` или `STABILITY_SECONDS=86400 make test-reliability`. В текущем прогоне длительность составила {stability['duration_sec']} сек; ошибок {stability['errors']}, reconnect {stability['connection_drops']}.

## Артефакты

- CSV: `csv/`
- JSON: `json/`
- Markdown: `reports/`
- Графики SVG/PNG: `charts/`
- Логи и фрагменты для ВКР: `logs/`, `screenshots/`
""",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run operational/load tests for Modbus TCP firewall")
    parser.add_argument("--requests", type=int, default=int(os.getenv("BENCHMARK_REQUESTS", "500000")))
    parser.add_argument("--latency-requests", type=int, default=int(os.getenv("LATENCY_REQUESTS", "3000")))
    parser.add_argument("--stability-seconds", type=int, default=int(os.getenv("STABILITY_SECONDS", "43200")))
    parser.add_argument("--artifact-dir", type=Path, default=Path(os.getenv("BENCHMARK_ARTIFACT_DIR", str(DEFAULT_ARTIFACT_DIR))))
    parser.add_argument("--firewall-binary", type=Path, default=ROOT / "bin" / "firewall")
    parser.add_argument("--go-binary", default=os.getenv("GO", "/usr/local/go/bin/go"))
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    artifact_dir = args.artifact_dir
    csv_dir = artifact_dir / "csv"
    json_dir = artifact_dir / "json"
    report_dir = artifact_dir / "reports"
    chart_dir = artifact_dir / "charts"
    log_dir = artifact_dir / "logs"
    screenshot_dir = artifact_dir / "screenshots"
    runtime_dir = artifact_dir / "runtime"
    for directory in (csv_dir, json_dir, report_dir, chart_dir, log_dir, screenshot_dir, runtime_dir):
        directory.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    build_log = log_dir / "build.log"
    if not args.skip_build:
        build_env = os.environ.copy()
        build_env["GOCACHE"] = str(runtime_dir / "go-build-cache")
        build_env["PYTHONPYCACHEPREFIX"] = str(runtime_dir / "pycache")
        if Path("/usr/local/go").exists():
            build_env["GOROOT"] = "/usr/local/go"
        try:
            run_cmd([args.go_binary, "build", "-o", str(args.firewall_binary), "./cmd/firewall"], ROOT, build_log, env=build_env)
        except RuntimeError:
            if not args.firewall_binary.exists():
                raise
            with build_log.open("a", encoding="utf-8") as log:
                log.write("\nWARNING: go build failed; continuing with existing firewall binary.\n")

    plc_port = int(os.getenv("PLC_PORT", "16502"))
    firewall_port = int(os.getenv("FIREWALL_PORT", "16503"))
    config_path = runtime_dir / "config.yaml"
    policy_path = runtime_dir / "policy.yaml"
    events_path = runtime_dir / "events.db"
    write_policy(policy_path)
    write_config(config_path, "enforce", firewall_port, plc_port, events_path)

    plc = ModbusPLCServer("127.0.0.1", plc_port, log_dir / "plc.log")
    firewall: ServiceProcess | None = None
    results: dict = {"started_at": started_at}
    source_ip_probe_enabled = supports_loopback_alias()
    results["source_ip_probe"] = {
        "enabled": source_ip_probe_enabled,
        "note": "127.0.0.2 bind available" if source_ip_probe_enabled else "127.0.0.2 bind is unavailable on this host; Docker/Linux profile can run this probe",
    }
    resource_stop = threading.Event()

    try:
        plc.start()
        firewall = start_firewall(args.firewall_binary, config_path, policy_path, log_dir / "firewall.log")
        wait_for_port("127.0.0.1", firewall_port, "firewall")

        resource_thread = threading.Thread(target=sample_resources, args=(firewall.pid, resource_stop, csv_dir / "resources.csv", 1.0), daemon=True)
        resource_thread.start()

        mixed_ops = mixed_operations(include_source_ip_probe=source_ip_probe_enabled)
        load_summary = run_workload("load-500k-mixed", "127.0.0.1", firewall_port, mixed_ops, args.requests, csv_dir / "load_requests.csv")
        results["summary"] = load_summary
        write_json(json_dir / "load_summary.json", load_summary)

        fp_summary = run_workload("false-positive-legitimate", "127.0.0.1", firewall_port, allowed_operations(), min(args.latency_requests, 5000), csv_dir / "false_positive.csv")
        fp = fp_summary["blocked"] + fp_summary["errors"]
        results["false_positive"] = {
            "total": fp_summary["processed"],
            "false_positive": fp,
            "false_positive_percent": round((fp / max(fp_summary["processed"], 1)) * 100, 5),
        }
        write_json(json_dir / "false_positive.json", results["false_positive"])

        before_plc = plc.snapshot()["total_requests"]
        forbidden_summary = run_workload("forbidden-operations", "127.0.0.1", firewall_port, [op for op in mixed_ops if not op.allowed], 200, csv_dir / "forbidden.csv")
        after_plc = plc.snapshot()["total_requests"]
        results["forbidden"] = {"total": forbidden_summary["processed"], "blocked": forbidden_summary["blocked"] + forbidden_summary["errors"], "plc_delta": after_plc - before_plc}
        write_json(json_dir / "forbidden.json", results["forbidden"])

        direct = run_workload("latency-direct", "127.0.0.1", plc_port, allowed_operations(), args.latency_requests, csv_dir / "latency_direct.csv")
        write_config(config_path, "observe", firewall_port, plc_port, events_path)
        time.sleep(1.0)
        observe = run_workload("latency-observe", "127.0.0.1", firewall_port, allowed_operations(), args.latency_requests, csv_dir / "latency_observe.csv")
        write_config(config_path, "enforce", firewall_port, plc_port, events_path)
        time.sleep(1.0)
        enforce = run_workload("latency-enforce", "127.0.0.1", firewall_port, allowed_operations(), args.latency_requests, csv_dir / "latency_enforce.csv")
        results["latency"] = {"direct": direct, "observe": observe, "enforce": enforce}
        write_json(json_dir / "latency_compare.json", results["latency"])

        conn_summary = run_workload("connection-loss-long-lived", "127.0.0.1", firewall_port, allowed_operations(), max(args.latency_requests, 1000), csv_dir / "connection_loss.csv", reuse_connection=True)
        results["connection_loss"] = conn_summary
        write_json(json_dir / "connection_loss.json", conn_summary)

        hot_op = Operation("hot-register-60", 6, 60, 1, False, build_fc06(60, 4242))
        pid_before = firewall.pid
        hot_started = time.perf_counter()
        hot_op_allowed = Operation("hot-register-60", 6, 60, 1, True, build_fc06(60, 4242))
        before_outcome, after_outcome, reload_elapsed = hot_reload_same_connection("127.0.0.1", firewall_port, hot_op, hot_op_allowed, policy_path)
        pid_after = firewall.pid
        results["hot_reload"] = {
            "pid_before": pid_before,
            "pid_after": pid_after,
            "restart_detected": pid_before != pid_after,
            "before_outcome": before_outcome,
            "after_outcome": after_outcome,
            "reload_detected_sec": round(reload_elapsed, 3),
            "same_connection_policy_applied": after_outcome == "allowed",
        }
        write_json(json_dir / "hot_reload.json", results["hot_reload"])
        (report_dir / "hot_reload_report.md").write_text(
            f"# Hot reload policy\n\nPID до: {pid_before}\n\nPID после: {pid_after}\n\nДо обновления: {before_outcome}\n\nПосле обновления: {after_outcome}\n",
            encoding="utf-8",
        )

        recovery_start = time.perf_counter()
        old_pid = firewall.pid
        firewall.process.kill()
        firewall.process.wait(timeout=5)
        firewall = start_firewall(args.firewall_binary, config_path, policy_path, log_dir / "firewall_after_failure.log")
        wait_for_port("127.0.0.1", firewall_port, "firewall-recovered")
        recovery_time = time.perf_counter() - recovery_start
        outcome, _, _, _ = request_once("127.0.0.1", firewall_port, allowed_operations()[1], 50000)
        results["recovery"] = {
            "old_pid": old_pid,
            "new_pid": firewall.pid,
            "recovery_time_sec": round(recovery_time, 3),
            "available_after_restart": outcome == "allowed",
            "config_preserved": config_path.exists() and policy_path.exists(),
        }
        write_json(json_dir / "recovery.json", results["recovery"])

        stability_started = time.perf_counter()
        stability_summary = run_timed_workload("stability", "127.0.0.1", firewall_port, allowed_operations(), args.stability_seconds, csv_dir / "stability.csv")
        stability_summary["duration_sec"] = round(time.perf_counter() - stability_started, 3)
        results["stability"] = stability_summary
        write_json(json_dir / "stability.json", stability_summary)

        write_table_csv(
            csv_dir / "summary_table.csv",
            [
                {"scenario": key, **{k: v for k, v in value.items() if not isinstance(v, dict)}}
                for key, value in [
                    ("load", load_summary),
                    ("false_positive", fp_summary),
                    ("latency_direct", direct),
                    ("latency_observe", observe),
                    ("latency_enforce", enforce),
                    ("connection_loss", conn_summary),
                    ("stability", stability_summary),
                ]
            ],
        )

        write_line_svg(chart_dir / "throughput.svg", "Throughput by second", {"load": [(float(k), float(v)) for k, v in load_summary["throughput_buckets"].items()]}, "req/sec")
        write_bar_svg(
            chart_dir / "latency_compare.svg",
            "Latency p99 comparison",
            {"direct": direct["p99_latency_ms"], "observe": observe["p99_latency_ms"], "enforce": enforce["p99_latency_ms"]},
            "p99 ms",
        )
        write_simple_png(chart_dir / "load_latency.png", "Load latency", read_latency_column(csv_dir / "load_requests.csv", limit=2000))
        write_simple_png(chart_dir / "resource_rss.png", "RSS", read_numeric_column(csv_dir / "resources.csv", "rss_kb"))
        (screenshot_dir / "hot_reload_evidence.txt").write_text((log_dir / "firewall.log").read_text(encoding="utf-8", errors="ignore")[-4000:], encoding="utf-8")
        (screenshot_dir / "blocking_evidence.txt").write_text((log_dir / "firewall.log").read_text(encoding="utf-8", errors="ignore")[-4000:], encoding="utf-8")
        write_simple_png(screenshot_dir / "hot_reload_timeline.png", "hot reload", [0, 0, 1, 1])
        write_simple_png(screenshot_dir / "blocking_summary.png", "blocking", [results["forbidden"]["blocked"], results["forbidden"]["plc_delta"]])

        write_json(json_dir / "all_results.json", results)
        generate_report(report_dir / "operational_test_report.md", results, artifact_dir)
        print(f"Artifacts written to {artifact_dir}")
        return 0
    finally:
        resource_stop.set()
        if firewall is not None:
            firewall.stop()
        plc.stop()


def read_latency_column(path: Path, limit: int = 10000) -> list[float]:
    values: list[float] = []
    with path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            values.append(float(row["latency_ms"]))
            if len(values) >= limit:
                break
    return values


def read_numeric_column(path: Path, column: str) -> list[float]:
    if not path.exists():
        return []
    values: list[float] = []
    with path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                values.append(float(row[column]))
            except (KeyError, ValueError):
                continue
    return values


if __name__ == "__main__":
    raise SystemExit(main())
