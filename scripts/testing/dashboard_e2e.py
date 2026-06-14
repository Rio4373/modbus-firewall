#!/usr/bin/env python3
"""End-to-end checks for the Modbus firewall dashboard stack."""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import URLError


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = ROOT / "artifacts" / "dashboard-e2e"
API_BASE = os.environ.get("DASHBOARD_API_BASE", "http://127.0.0.1:18080")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://127.0.0.1:3000")
COMPOSE = os.environ.get("DOCKER_COMPOSE", "docker compose").split()
RESET_STATE = os.environ.get("DASHBOARD_E2E_RESET_STATE", "1") != "0"


class CheckFailure(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def http_json(path: str, method: str = "GET", body: dict[str, Any] | None = None, timeout: int = 10) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = request.Request(f"{API_BASE}{path}", data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def http_text(url: str, timeout: int = 10) -> str:
    with request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def compose_exec(*args: str) -> str:
    proc = subprocess.run(
        [*COMPOSE, "exec", "-T", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise CheckFailure(proc.stdout.strip() or f"docker compose exec failed: {' '.join(args)}")
    return proc.stdout


def compose(*args: str, timeout: int = 60) -> str:
    proc = subprocess.run(
        [*COMPOSE, *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise CheckFailure(proc.stdout.strip() or f"docker compose failed: {' '.join(args)}")
    return proc.stdout


def prepare_clean_state() -> list[str]:
    if not RESET_STATE:
        return []

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    backup_dir = ARTIFACT_DIR / "backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir.mkdir(parents=True, exist_ok=True)

    compose("stop", "firewall", timeout=60)
    moved: list[str] = []
    data_dir = ROOT / "data"
    for name in ("events.db", "events.db-wal", "events.db-shm"):
        source = data_dir / name
        if source.exists():
            target = backup_dir / name
            source.replace(target)
            moved.append(str(target))
    compose("up", "-d", "firewall", "dashboard", "arm-sim", timeout=90)
    return moved


def wait_api(timeout: int = 60) -> dict[str, Any]:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            status = http_json("/api/status")
            if status.get("status") == "online":
                return status
        except (URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise CheckFailure(f"API is not online: {last_error}")


def wait_mode(mode: str, timeout: int = 20) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = http_json("/api/status")
        if status.get("mode") == mode:
            return status
        time.sleep(0.5)
    raise CheckFailure(f"mode did not switch to {mode}")


def arm_scenario(scenario: str, *extra: str) -> dict[str, Any]:
    output = compose_exec("arm-sim", "arm-sim", "--target", "firewall:1502", "--scenario", scenario, *extra)
    match = re.search(r"ARM sim итог: ok=(\d+) exceptions=(\d+) errors=(\d+) total=(\d+)", output)
    if not match:
        raise CheckFailure(f"arm-sim summary not found for {scenario}: {output}")
    return {
        "scenario": scenario,
        "output": output.strip(),
        "ok": int(match.group(1)),
        "exceptions": int(match.group(2)),
        "errors": int(match.group(3)),
        "total": int(match.group(4)),
    }


def unauthorized_source_request() -> dict[str, Any]:
    transaction_id = 0x1001
    unit_id = 1
    pdu = struct.pack(">BHH", 6, 0, 1)
    packet = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", 1502), timeout=5) as sock:
        sock.sendall(packet)
        response = sock.recv(260)
    latency_ms = (time.perf_counter() - started) * 1000
    if len(response) < 9:
        raise CheckFailure(f"short response for unauthorized source: {response.hex(' ')}")
    function_code = response[7]
    exception_code = response[8] if function_code & 0x80 else None
    return {
        "response_hex": response.hex(" "),
        "latency_ms": round(latency_ms, 3),
        "blocked": bool(function_code & 0x80),
        "function_code": function_code,
        "exception_code": exception_code,
    }


def add_result(results: list[dict[str, Any]], name: str, passed: bool, details: Any) -> None:
    results.append({"name": name, "passed": passed, "details": details})
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def write_report(results: list[dict[str, Any]], payload: dict[str, Any]) -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    results_path = ARTIFACT_DIR / "dashboard_e2e_results.json"
    report_path = ARTIFACT_DIR / "dashboard_e2e_report.md"
    results_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    passed = sum(1 for item in results if item["passed"])
    total = len(results)
    rows = "\n".join(
        f"| {item['name']} | {'PASS' if item['passed'] else 'FAIL'} | `{str(item['details']).replace('|', '/')[:180]}` |"
        for item in results
    )
    report = f"""# Dashboard E2E отчет

Дата запуска: {payload['started_at']}

Итог: {passed}/{total} проверок пройдено.

| Проверка | Статус | Детали |
|---|---:|---|
{rows}

## Ключевые показатели

| Показатель | Значение |
|---|---:|
| Режим после теста | {payload.get('final_status', {}).get('mode', '-')} |
| PID firewall | {payload.get('final_status', {}).get('pid', '-')} |
| Правил active policy | {payload.get('final_status', {}).get('policy_rules', '-')} |
| Обработано запросов | {payload.get('final_metrics', {}).get('processed_requests', '-')} |
| Разрешено запросов | {payload.get('final_metrics', {}).get('allowed_requests', '-')} |
| Заблокировано запросов | {payload.get('final_metrics', {}).get('blocked_requests', '-')} |
| Ошибки обработки | {payload.get('final_metrics', {}).get('errors', '-')} |
| Потери соединений | {payload.get('final_metrics', {}).get('connection_losses', '-')} |
| Средняя задержка, мс | {payload.get('final_metrics', {}).get('avg_latency_ms', '-')} |
| p95, мс | {payload.get('final_metrics', {}).get('p95_latency_ms', '-')} |
| p99, мс | {payload.get('final_metrics', {}).get('p99_latency_ms', '-')} |

Артефакты: `dashboard_e2e_results.json`, `dashboard_e2e_report.md`.
"""
    report_path.write_text(report, encoding="utf-8")


def main() -> int:
    results: list[dict[str, Any]] = []
    payload: dict[str, Any] = {
        "started_at": now_iso(),
        "api_base": API_BASE,
        "dashboard_url": DASHBOARD_URL,
        "checks": results,
        "reset_state": RESET_STATE,
    }

    try:
        backups = prepare_clean_state()
        payload["state_backups"] = backups
        if backups:
            add_result(results, "История событий очищена с backup предыдущей БД", True, backups)

        status = wait_api()
        add_result(results, "API доступен и firewall online", True, status)

        html = http_text(DASHBOARD_URL)
        assert_true('<div id="root">' in html and "Межсетевой экран Modbus TCP" in html, "dashboard root markup not found")
        add_result(results, "Dashboard UI отдается через HTTP", True, {"bytes": len(html)})

        initial_pid = int(status["pid"])
        http_json("/api/mode", method="POST", body={"mode": "ANALYZE"})
        analyze_status = wait_mode("ANALYZE")
        assert_true(int(analyze_status["pid"]) == initial_pid, "PID changed after ANALYZE switch")
        add_result(results, "Переключение в ANALYZE без рестарта", True, analyze_status)

        normal = arm_scenario("normal-read")
        repeated = arm_scenario("repeated-write", "--repeat", "3")
        rare = arm_scenario("rare-write")
        assert_true(normal["ok"] == 3 and normal["errors"] == 0, normal["output"])
        assert_true(repeated["ok"] == 3 and repeated["errors"] == 0, repeated["output"])
        assert_true(rare["ok"] == 1 and rare["errors"] == 0, rare["output"])
        add_result(results, "Штатный профиль Modbus накоплен в ANALYZE", True, [normal, repeated, rare])

        generated = http_json("/api/policies/generate", method="POST", body={"write_threshold": 1})
        summary = generated["summary"]
        assert_true(summary["write_threshold"] == 1, f"unexpected threshold: {summary}")
        assert_true(summary["write_operations_excluded"] == 0, f"write operations excluded: {summary}")
        add_result(results, "Candidate policy сформирована с writeThreshold=1", True, summary)

        candidate_report = http_json("/api/policies/candidate/verify", method="POST", body={})
        assert_true(candidate_report["uncovered_historical_requests"] == 0, candidate_report)
        assert_true(candidate_report["false_positive"] == 0, candidate_report)
        add_result(results, "Candidate verification: покрытие истории 100%, false positive 0", True, candidate_report)

        applied = http_json("/api/policies/candidate/apply", method="POST", body={})
        assert_true(applied.get("pid_before") == applied.get("pid_after"), applied)
        assert_true(applied.get("connection_losses") == 0, applied)
        filter_status = wait_mode("FILTER")
        assert_true(int(filter_status["pid"]) == initial_pid, "PID changed after policy apply")
        add_result(results, "Apply candidate: hot reload без restart и потерь", True, applied)

        active_report = http_json("/api/policies/active/verify", method="POST", body={})
        assert_true(active_report["uncovered_historical_requests"] == 0, active_report)
        assert_true(active_report["false_positive"] == 0, active_report)
        add_result(results, "Active verification: покрытие истории 100%, false positive 0", True, active_report)

        blocked = unauthorized_source_request()
        assert_true(blocked["blocked"], blocked)
        add_result(results, "Запрос от неразрешенного источника блокируется", True, blocked)

        active_after_block = http_json("/api/policies/active/verify", method="POST", body={})
        assert_true(active_after_block["uncovered_historical_requests"] == 0, active_after_block)
        assert_true(active_after_block["excluded_forbidden_requests"] >= 1, active_after_block)
        add_result(results, "Заблокированная атака не ухудшает coverage штатной policy", True, active_after_block)

        final_metrics = http_json("/api/metrics")
        assert_true(final_metrics["errors"] == 0, final_metrics)
        assert_true(final_metrics["connection_losses"] == 0, final_metrics)
        add_result(results, "Метрики после e2e без ошибок и потерь соединений", True, final_metrics)

        payload["final_status"] = http_json("/api/status")
        payload["final_metrics"] = final_metrics
        payload["finished_at"] = now_iso()
        write_report(results, payload)
        print(f"Artifacts: {ARTIFACT_DIR}")
        return 0
    except Exception as exc:
        add_result(results, "E2E остановлен из-за ошибки", False, str(exc))
        try:
            payload["final_status"] = http_json("/api/status")
            payload["final_metrics"] = http_json("/api/metrics")
        except Exception:
            pass
        payload["finished_at"] = now_iso()
        write_report(results, payload)
        print(f"Artifacts: {ARTIFACT_DIR}", file=sys.stderr)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
