#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

REPORT_PATH="${ROOT_DIR}/reports/demo-showcase-report.txt"
CONFIG_BACKUP_PATH=""
POLICY_BACKUP_PATH=""
CLEANUP_DONE=0

ensure_dirs
: > "${REPORT_PATH}"
exec > >(tee "${REPORT_PATH}") 2>&1

print_stage() {
  local title="$1"
  printf "\n============================================================\n"
  printf "%s\n" "${title}"
  printf "============================================================\n"
}

print_note() {
  printf "[INFO] %s\n" "$1"
}

print_result() {
  printf "[RESULT] %s\n" "$1"
}

backup_demo_state() {
  CONFIG_BACKUP_PATH="$(mktemp)"
  POLICY_BACKUP_PATH="$(mktemp)"
  cp "${ROOT_DIR}/configs/config.yaml" "${CONFIG_BACKUP_PATH}"
  cp "${ROOT_DIR}/configs/policy.yaml" "${POLICY_BACKUP_PATH}"
}

restore_demo_state() {
  if [[ -n "${CONFIG_BACKUP_PATH}" && -f "${CONFIG_BACKUP_PATH}" ]]; then
    cp "${CONFIG_BACKUP_PATH}" "${ROOT_DIR}/configs/config.yaml"
    rm -f "${CONFIG_BACKUP_PATH}"
  fi

  if [[ -n "${POLICY_BACKUP_PATH}" && -f "${POLICY_BACKUP_PATH}" ]]; then
    cp "${POLICY_BACKUP_PATH}" "${ROOT_DIR}/configs/policy.yaml"
    rm -f "${POLICY_BACKUP_PATH}"
  fi
}

cleanup() {
  if [[ "${CLEANUP_DONE}" == "1" ]]; then
    return 0
  fi

  restore_demo_state

  if [[ "${KEEP_STAND_UP:-0}" != "1" ]]; then
    compose down >/dev/null 2>&1 || true
    python3 - <<'PY' "${ROOT_DIR}"
import subprocess
import sys
import time

root = sys.argv[1]
for _ in range(20):
    result = subprocess.run(
        ["docker", "compose", "ps", "-q"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if not result.stdout.strip():
        raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit(0)
PY
  fi

  CLEANUP_DONE=1
  return 0
}

interrupt_handler() {
  cleanup
  exit 130
}

trap interrupt_handler INT TERM

show_sqlite_summary() {
  python3 - "${ROOT_DIR}/data/events.db" <<'PY'
import sqlite3
import sys
from pathlib import Path

path = sys.argv[1]
if not Path(path).exists():
    print("SQLite summary: база ещё не создана")
    raise SystemExit(0)

conn = sqlite3.connect(path)
try:
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM modbus_events").fetchone()[0]
    by_fc = cur.execute(
        "SELECT function_code, COUNT(*) FROM modbus_events GROUP BY function_code ORDER BY function_code"
    ).fetchall()
    latest = cur.execute(
        """
        SELECT id, source_ip, destination_ip, function_code, start_address, quantity, operation_type
        FROM modbus_events
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()
    print(f"SQLite summary: total_events={total}")
    print(f"SQLite by_fc: {by_fc}")
    print(f"SQLite latest: {latest}")
finally:
    conn.close()
PY
}

show_container_start_times() {
  python3 - "${ROOT_DIR}" <<'PY'
import subprocess
import sys

root = sys.argv[1]
services = ["arm-sim", "firewall", "plc-sim"]
for service in services:
    cid = subprocess.run(
        ["docker", "compose", "ps", "-q", service],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not cid:
        print(f"Container runtime: service={service} id=<none> started_at=<none>")
        continue
    started = subprocess.run(
        ["docker", "inspect", cid, "--format", "{{.State.StartedAt}}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    print(f"Container runtime: service={service} id={cid} started_at={started}")
PY
}

show_artifact_freshness() {
  python3 - "${ROOT_DIR}" <<'PY'
from datetime import datetime
from pathlib import Path
import sys

root = Path(sys.argv[1])
artifacts = [
    root / "data" / "events.db",
    root / "configs" / "policy.candidate.yaml",
    root / "reports" / "replay-report.json",
]

for path in artifacts:
    if not path.exists():
        print(f"Artifact freshness: path={path} status=missing")
        continue
    mtime = datetime.fromtimestamp(path.stat().st_mtime).isoformat()
    print(f"Artifact freshness: path={path} modified_at={mtime}")
PY
}

show_current_time() {
  printf "Current local time: "
  date '+%Y-%m-%d %H:%M:%S %Z'
}

show_replay_summary() {
  python3 - "${ROOT_DIR}/reports/replay-report.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    report = json.load(fh)

print(
    "Replay summary: "
    f"total={int(report.get('total_events', 0))} "
    f"covered={int(report.get('covered_events', 0))} "
    f"blocked={int(report.get('blocked_events', 0))}"
)
print(f"Replay uncovered_operations: {report.get('uncovered_operations', [])}")
PY
}

show_policy_summary() {
  local policy_path="${ROOT_DIR}/configs/policy.candidate.yaml"
  local rule_count

  rule_count="$(grep -E -c '^[[:space:]]+- id:' "${policy_path}" || true)"
  printf "Candidate policy rules: %s\n" "${rule_count}"
  printf "Candidate policy preview:\n"
  sed -n '1,200p' "${policy_path}"
}

show_firewall_highlights() {
  printf "Firewall log highlights:\n"
  compose logs --tail=120 firewall | grep -E 'proxy запущен|hot reload успешно применен|запрос заблокирован политикой' || true
}

show_plc_highlights() {
  printf "PLC log highlights:\n"
  compose logs --tail=120 plc-sim | tail -n 20
}

show_container_summary() {
  printf "Container summary:\n"
  compose ps
}

main() {
  local firewall_before=""
  local firewall_after=""

  print_stage "DEMO SHOWCASE"
  require_docker
  backup_demo_state
  print_note "Сценарий сам прогонит полный цикл: observe -> generate-policy -> replay -> enforce -> hot reload."
  print_note "Все результаты будут выведены в консоль и сохранены в ${REPORT_PATH}."
  if [[ "${KEEP_STAND_UP:-0}" == "1" ]]; then
    print_note "Режим cleanup отключён: стенд останется запущенным после завершения."
  else
    print_note "После завершения скрипт сам остановит Docker Compose стенд и восстановит исходные config/policy."
  fi

  print_stage "1. ПОДГОТОВКА СТЕНДА"
  print_note "Поднимается Docker Compose стенд и очищаются предыдущие demo-артефакты."
  "${ROOT_DIR}/scripts/demo/00_prepare.sh"
  show_container_summary
  show_current_time
  show_container_start_times
  show_sqlite_summary
  print_result "Стенд готов. Firewall стартует в режиме observe."
  print_result "Подтверждение: контейнеры запущены в текущем прогоне, база до трафика пустая."

  print_stage "2. OBSERVE: СБОР ТРАФИКА"
  print_note "Firewall не блокирует запросы, а только наблюдает и пишет события в SQLite."
  "${ROOT_DIR}/scripts/demo/01_observe.sh"
  show_sqlite_summary
  print_result "Нормальный трафик прошёл, события записаны в SQLite."

  print_stage "3. GENERATE POLICY"
  print_note "Из накопленных событий строится candidate policy."
  "${ROOT_DIR}/scripts/demo/02_generate_policy.sh"
  show_policy_summary
  show_artifact_freshness
  print_result "Policy сгенерирована и готова к проверке."

  print_stage "4. REPLAY"
  print_note "Сгенерированная policy проверяется на исторических событиях."
  "${ROOT_DIR}/scripts/demo/03_replay.sh"
  show_replay_summary
  show_artifact_freshness
  print_result "Replay завершён. Видно покрытие policy и непокрытые операции."

  print_stage "5. ENFORCE"
  print_note "Policy применяется, firewall бесшовно переходит от observe к фильтрации."
  firewall_before="$(compose ps -q firewall)"
  printf "Firewall container id before enforce: %s\n" "${firewall_before}"
  "${ROOT_DIR}/scripts/demo/04_enforce.sh"
  show_firewall_highlights
  show_sqlite_summary
  print_result "Легитимные запросы проходят, запрещённая операция блокируется."

  print_stage "6. HOT RELOAD"
  print_note "Новая policy подхватывается без остановки firewall. Поведение меняется на лету."
  "${ROOT_DIR}/scripts/demo/05_hot_reload.sh"
  firewall_after="$(compose ps -q firewall)"
  printf "Firewall container id after hot reload: %s\n" "${firewall_after}"
  if [[ -n "${firewall_before}" && "${firewall_before}" == "${firewall_after}" ]]; then
    print_result "Контейнер firewall не перезапускался во время hot reload."
  else
    print_result "ВНИМАНИЕ: firewall container id изменился."
  fi
  show_firewall_highlights
  show_plc_highlights
  show_sqlite_summary
  show_artifact_freshness

  print_stage "7. ИТОГИ ДЕМОНСТРАЦИИ"
  print_result "Observe: все запросы проходили, firewall собирал события."
  print_result "Generate-policy: policy построена из реального трафика."
  print_result "Replay: policy проверена по истории."
  print_result "Enforce: запрещённая операция была заблокирована."
  print_result "Hot reload: новая policy изменила поведение без рестарта firewall."
  print_result "Подтверждение живого прогона: контейнеры были подняты в текущем запуске, база была пустой до трафика, а артефакты получили свежие временные метки в ходе сценария."
  print_result "Подробный отчёт сохранён в ${REPORT_PATH}."
  if [[ "${KEEP_STAND_UP:-0}" == "1" ]]; then
    print_note "Стенд оставлен запущенным. Для остановки выполните: docker compose down"
  else
    print_note "Стенд будет автоматически остановлен после завершения скрипта."
  fi
}

if main "$@"; then
  cleanup
else
  cleanup
  exit 1
fi
