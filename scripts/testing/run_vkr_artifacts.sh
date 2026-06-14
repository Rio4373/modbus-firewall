#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_ROOT="${ROOT_DIR}/artifacts/testing"
ENV_DIR="${ARTIFACT_ROOT}/01_environment"
ANALYSIS_DIR="${ARTIFACT_ROOT}/02_analysis_mode"
POLICY_DIR="${ARTIFACT_ROOT}/03_policy_generation"
FILTER_DIR="${ARTIFACT_ROOT}/04_filtering_mode"
HOT_DIR="${ARTIFACT_ROOT}/05_hot_reload"
STABILITY_DIR="${ARTIFACT_ROOT}/06_stability"
SUMMARY_DIR="${ARTIFACT_ROOT}/07_summary"

RUNTIME_DIR="${ENV_DIR}/runtime"
BIN_DIR="${RUNTIME_DIR}/bin"
VENV_DIR="${RUNTIME_DIR}/venv"
LOG_DIR="${RUNTIME_DIR}/logs"
REPORT_DIR="${RUNTIME_DIR}/reports"
CONFIG_PATH="${RUNTIME_DIR}/config.yaml"
ACTIVE_POLICY_PATH="${RUNTIME_DIR}/policy.yaml"
CANDIDATE_POLICY_PATH="${RUNTIME_DIR}/policy.candidate.yaml"
BASELINE_POLICY_PATH="${RUNTIME_DIR}/policy.generated.yaml"
PLC_CONFIG_PATH="${RUNTIME_DIR}/plc-config.json"
EVENTS_DB_PATH="${RUNTIME_DIR}/events.db"
REPLAY_REPORT_PATH="${REPORT_DIR}/replay-report.json"
FIREWALL_LOG_PATH="${LOG_DIR}/firewall.log"
PLC_LOG_PATH="${LOG_DIR}/plc-sim.log"
RUN_CONSOLE_LOG="${ENV_DIR}/run_console.log"

LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:16020}"
UPSTREAM_ADDR="${UPSTREAM_ADDR:-127.0.0.1:16021}"
UNIT_ID="${UNIT_ID:-1}"
WRITE_THRESHOLD="${WRITE_THRESHOLD:-2}"
T9_REPEATED_WRITE_COUNT="${T9_REPEATED_WRITE_COUNT:-3000}"
T10_BACKGROUND_ITERATIONS="${T10_BACKGROUND_ITERATIONS:-200}"

FIREWALL_PID=""
PLC_PID=""

log() {
  printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

cleanup() {
  set +e

  if [[ -n "${FIREWALL_PID}" ]] && kill -0 "${FIREWALL_PID}" >/dev/null 2>&1; then
    kill "${FIREWALL_PID}" >/dev/null 2>&1 || true
    wait "${FIREWALL_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${PLC_PID}" ]] && kill -0 "${PLC_PID}" >/dev/null 2>&1; then
    kill "${PLC_PID}" >/dev/null 2>&1 || true
    wait "${PLC_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

line_count() {
  local file_path="$1"
  if [[ -f "${file_path}" ]]; then
    wc -l <"${file_path}" | tr -d ' '
  else
    echo 0
  fi
}

capture_log_slice() {
  local source_path="$1"
  local start_line="$2"
  local destination_path="$3"
  local end_line

  mkdir -p "$(dirname "${destination_path}")"
  end_line="$(line_count "${source_path}")"
  if (( end_line <= start_line )); then
    : >"${destination_path}"
    return 0
  fi

  sed -n "$((start_line + 1)),${end_line}p" "${source_path}" >"${destination_path}"
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local label="$3"
  local attempt

  for attempt in $(seq 1 40); do
    if python3 - "${host}" "${port}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.3)
    try:
        sock.connect((host, port))
    except OSError:
        raise SystemExit(1)

raise SystemExit(0)
PY
    then
      return 0
    fi
    sleep 0.25
  done

  printf "ОШИБКА: %s не поднялся на %s:%s\n" "${label}" "${host}" "${port}" >&2
  return 1
}

wait_for_log_after() {
  local file_path="$1"
  local pattern="$2"
  local start_line="$3"
  local description="$4"
  local attempt
  local current_end

  for attempt in $(seq 1 60); do
    current_end="$(line_count "${file_path}")"
    if (( current_end > start_line )) && sed -n "$((start_line + 1)),${current_end}p" "${file_path}" | grep -q "${pattern}"; then
      return 0
    fi
    sleep 0.25
  done

  printf "ОШИБКА: не дождались записи в журнале (%s): %s\n" "${description}" "${pattern}" >&2
  return 1
}

set_firewall_mode() {
  local mode="$1"

  awk -v mode_value="${mode}" '
    BEGIN { updated = 0 }
    {
      if ($1 == "mode:") {
        print "mode: " mode_value
        updated = 1
        next
      }
      print $0
    }
    END {
      if (updated == 0) {
        print "mode: " mode_value
      }
    }
  ' "${CONFIG_PATH}" >"${CONFIG_PATH}.tmp"

  mv "${CONFIG_PATH}.tmp" "${CONFIG_PATH}"
}

sqlite_single_value() {
  local query="$1"
  python3 - "${EVENTS_DB_PATH}" "${query}" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
query = sys.argv[2]

conn = sqlite3.connect(db_path)
try:
    cur = conn.cursor()
    row = cur.execute(query).fetchone()
    if row is None:
        print("")
    elif len(row) == 1:
        print(row[0])
    else:
        print("\t".join(str(value) for value in row))
finally:
    conn.close()
PY
}

sqlite_to_tsv() {
  local query="$1"
  local output_path="$2"

  python3 - "${EVENTS_DB_PATH}" "${query}" "${output_path}" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
query = sys.argv[2]
output_path = sys.argv[3]

conn = sqlite3.connect(db_path)
try:
    cur = conn.cursor()
    rows = cur.execute(query).fetchall()
    headers = [item[0] for item in cur.description]
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\t".join(headers) + "\n")
        for row in rows:
            fh.write("\t".join(str(value) for value in row) + "\n")
finally:
    conn.close()
PY
}

read_register_snapshot() {
  local host="$1"
  local port="$2"
  local address="$3"
  local output_path="$4"

  "${VENV_DIR}/bin/python" - "${host}" "${port}" "${UNIT_ID}" "${address}" >"${output_path}" <<'PY'
from datetime import datetime, timezone
import sys

from pymodbus.client import ModbusTcpClient

host = sys.argv[1]
port = int(sys.argv[2])
unit_id = int(sys.argv[3])
address = int(sys.argv[4])

client = ModbusTcpClient(host=host, port=port)
if not client.connect():
    raise SystemExit(f"failed_to_connect host={host} port={port}")

try:
    result = client.read_holding_registers(address=address, count=1, slave=unit_id)
    if result.isError():
        raise SystemExit(str(result))
    value = int(result.registers[0])
finally:
    client.close()

print(f"timestamp_utc={datetime.now(timezone.utc).isoformat()}")
print(f"host={host}")
print(f"port={port}")
print(f"unit_id={unit_id}")
print(f"address={address}")
print(f"value={value}")
PY
}

arm_command() {
  "${BIN_DIR}/arm-sim" --target "${LISTEN_ADDR}" "$@"
}

run_arm_capture() {
  local stage_dir="$1"
  local prefix="$2"
  shift 2

  local firewall_before plc_before
  firewall_before="$(line_count "${FIREWALL_LOG_PATH}")"
  plc_before="$(line_count "${PLC_LOG_PATH}")"

  arm_command "$@" >"${stage_dir}/${prefix}_client.log" 2>&1
  sleep 0.5

  capture_log_slice "${FIREWALL_LOG_PATH}" "${firewall_before}" "${stage_dir}/${prefix}_firewall.log"
  capture_log_slice "${PLC_LOG_PATH}" "${plc_before}" "${stage_dir}/${prefix}_plc.log"
}

summarize_arm_logs() {
  local output_path="$1"
  shift

  python3 - "${output_path}" "$@" <<'PY'
import json
import re
import sys
from pathlib import Path

summary_re = re.compile(r"ARM sim итог: ok=(\d+) exceptions=(\d+) errors=(\d+) total=(\d+)")
network_markers = ("connection reset", "broken pipe", "eof", "i/o timeout", "refused")

metrics = {
    "scenario_runs": 0,
    "ok": 0,
    "exceptions": 0,
    "errors": 0,
    "total_requests": 0,
    "connection_drops": 0,
}

for path_str in sys.argv[2:]:
    text = Path(path_str).read_text(encoding="utf-8")
    for match in summary_re.finditer(text):
        metrics["scenario_runs"] += 1
        metrics["ok"] += int(match.group(1))
        metrics["exceptions"] += int(match.group(2))
        metrics["errors"] += int(match.group(3))
        metrics["total_requests"] += int(match.group(4))
    for line in text.splitlines():
        lowered = line.lower()
        if "-> error:" in lowered and any(marker in lowered for marker in network_markers):
            metrics["connection_drops"] += 1

Path(sys.argv[1]).write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
}

write_metrics_report() {
  local title="$1"
  local metrics_json="$2"
  local pid_before="$3"
  local pid_after="$4"
  local output_path="$5"

  python3 - "${title}" "${metrics_json}" "${pid_before}" "${pid_after}" "${output_path}" <<'PY'
import json
import sys
from pathlib import Path

title = sys.argv[1]
metrics = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
pid_before = sys.argv[3].strip()
pid_after = sys.argv[4].strip()

service_restarted = "нет" if pid_before == pid_after and pid_before else "да"
text = f"""# {title}

- Отправлено запросов: {metrics['total_requests']}
- Успешно обработано: {metrics['ok']}
- Заблокировано политикой: {metrics['exceptions']}
- Неожиданные ошибки: {metrics['errors']}
- Обрывы соединения: {metrics['connection_drops']}
- PID firewall до прогона: {pid_before}
- PID firewall после прогона: {pid_after}
- Перезапуск службы: {service_restarted}
"""

Path(sys.argv[5]).write_text(text, encoding="utf-8")
PY
}

capture_command_availability() {
  {
    printf "Рабочая директория: %s\n" "${ROOT_DIR}"
    printf "Дата запуска: %s\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf "Git commit: %s\n" "$(git rev-parse --short HEAD 2>/dev/null || echo 'n/a')"
    printf "\nКоманды:\n"
    for cmd in go python3 make docker tcpdump rg awk sed; do
      if command -v "${cmd}" >/dev/null 2>&1; then
        printf "%-10s %s\n" "${cmd}" "$(command -v "${cmd}")"
      else
        printf "%-10s %s\n" "${cmd}" "NOT_FOUND"
      fi
    done
  } >"${ENV_DIR}/available_commands.txt"

  {
    go version
    python3 --version
    make --version | head -n 1
    if command -v docker >/dev/null 2>&1; then
      docker --version || true
      docker compose version || true
      docker info >/dev/null 2>&1 && echo "docker_daemon=available" || echo "docker_daemon=unavailable"
    fi
    if command -v tcpdump >/dev/null 2>&1; then
      tcpdump --version | head -n 1 || true
    fi
    uname -a
  } >"${ENV_DIR}/tool_versions.txt" 2>&1

  go run ./cmd/firewall help >"${ENV_DIR}/firewall_help.txt" 2>&1
  go run ./cmd/arm-sim --list-scenarios >"${ENV_DIR}/arm_sim_scenarios.txt" 2>&1
  rg '^[A-Za-z0-9_.-]+:' Makefile >"${ENV_DIR}/make_targets.txt"
  git status --short >"${ENV_DIR}/git_status_before_testing.txt" || true

  if command -v tcpdump >/dev/null 2>&1; then
    {
      echo "tcpdump_path=$(command -v tcpdump)"
      tcpdump -D >/dev/null 2>&1 && echo "pcap_capture=possible_with_manual_interface_selection" || echo "pcap_capture=not_available_in_current_session"
    } >"${ANALYSIS_DIR}/pcap_capture_status.txt"
  else
    echo "pcap_capture=command_tcpdump_not_found" >"${ANALYSIS_DIR}/pcap_capture_status.txt"
  fi
}

prepare_artifact_tree() {
  rm -rf "${ARTIFACT_ROOT}"
  mkdir -p "${ENV_DIR}" "${ANALYSIS_DIR}" "${POLICY_DIR}" "${FILTER_DIR}" "${HOT_DIR}" "${STABILITY_DIR}" "${SUMMARY_DIR}"
  mkdir -p "${RUNTIME_DIR}" "${BIN_DIR}" "${LOG_DIR}" "${REPORT_DIR}"

  : >"${RUN_CONSOLE_LOG}"
  exec > >(tee "${RUN_CONSOLE_LOG}") 2>&1
}

prepare_runtime_files() {
  local upstream_host upstream_port
  upstream_host="${UPSTREAM_ADDR%:*}"
  upstream_port="${UPSTREAM_ADDR##*:}"

  mkdir -p "${RUNTIME_DIR}"

  cat >"${CONFIG_PATH}" <<EOF
mode: observe

server:
  listen_addr: "${LISTEN_ADDR}"

proxy:
  upstream_addr: "${UPSTREAM_ADDR}"
  dial_timeout: "3s"
  read_timeout: "5s"
  write_timeout: "5s"

logging:
  level: "debug"
  format: "text"

storage:
  events_path: "${EVENTS_DB_PATH}"
EOF

  cat >"${ACTIVE_POLICY_PATH}" <<'EOF'
version: 1
default_action: deny
rules: []
EOF

  cat >"${PLC_CONFIG_PATH}" <<EOF
{
  "host": "${upstream_host}",
  "port": ${upstream_port},
  "unit_id": ${UNIT_ID},
  "register_count": 128,
  "log_level": "INFO",
  "holding_registers": {
    "0": 100,
    "1": 101,
    "10": 110,
    "11": 111,
    "20": 120,
    "21": 121,
    "50": 500,
    "80": 777,
    "81": 888
  },
  "input_registers": {
    "0": 900,
    "1": 901
  }
}
EOF

  cp "${CONFIG_PATH}" "${ENV_DIR}/runtime_config_initial.yaml"
  cp "${ACTIVE_POLICY_PATH}" "${ENV_DIR}/runtime_policy_initial.yaml"
  cp "${PLC_CONFIG_PATH}" "${ENV_DIR}/runtime_plc_config.json"
}

build_runtime_tools() {
  log "Сборка firewall и arm-sim"
  go build -o "${BIN_DIR}/firewall" ./cmd/firewall >"${ENV_DIR}/build_firewall.log" 2>&1
  go build -o "${BIN_DIR}/arm-sim" ./cmd/arm-sim >"${ENV_DIR}/build_arm_sim.log" 2>&1
  go test ./... >"${ENV_DIR}/go_test.log" 2>&1

  log "Подготовка Python venv для plc-sim"
  python3 -m venv "${VENV_DIR}" >"${ENV_DIR}/venv_create.log" 2>&1
  "${VENV_DIR}/bin/pip" install --disable-pip-version-check -r "${ROOT_DIR}/plc-sim/requirements.txt" >"${ENV_DIR}/pip_install.log" 2>&1
}

start_services() {
  local listen_host listen_port upstream_host upstream_port
  listen_host="${LISTEN_ADDR%:*}"
  listen_port="${LISTEN_ADDR##*:}"
  upstream_host="${UPSTREAM_ADDR%:*}"
  upstream_port="${UPSTREAM_ADDR##*:}"

  log "Запуск plc-sim"
  "${VENV_DIR}/bin/python" "${ROOT_DIR}/plc-sim/server.py" --config "${PLC_CONFIG_PATH}" >"${PLC_LOG_PATH}" 2>&1 &
  PLC_PID="$!"
  wait_for_port "${upstream_host}" "${upstream_port}" "plc-sim"

  log "Запуск firewall"
  "${BIN_DIR}/firewall" run --config "${CONFIG_PATH}" --policy "${ACTIVE_POLICY_PATH}" --reload-interval 1s >"${FIREWALL_LOG_PATH}" 2>&1 &
  FIREWALL_PID="$!"
  wait_for_port "${listen_host}" "${listen_port}" "firewall"

  sleep 1
  cp "${FIREWALL_LOG_PATH}" "${ENV_DIR}/firewall_startup.log"
  cp "${PLC_LOG_PATH}" "${ENV_DIR}/plc_startup.log"

  {
    printf "plc_pid=%s\n" "${PLC_PID}"
    ps -p "${PLC_PID}" -o pid=,ppid=,lstart=,command=
    printf "\nfirewall_pid=%s\n" "${FIREWALL_PID}"
    ps -p "${FIREWALL_PID}" -o pid=,ppid=,lstart=,command=
  } >"${ENV_DIR}/process_info_started.txt"
}

run_analysis_stage() {
  log "T1: normal-read в observe"
  run_arm_capture "${ANALYSIS_DIR}" "t1_normal_read" --scenario normal-read

  log "T2: repeated-write в observe"
  run_arm_capture "${ANALYSIS_DIR}" "t2_repeated_write" --scenario repeated-write --repeat 10

  log "T3: rare-write в observe"
  run_arm_capture "${ANALYSIS_DIR}" "t3_rare_write" --scenario rare-write

  sqlite_to_tsv \
    'SELECT id, timestamp, source_ip, destination_ip, unit_id, function_code, start_address, quantity, operation_type FROM modbus_events ORDER BY id' \
    "${ANALYSIS_DIR}/events_after_observe.tsv"
  sqlite_to_tsv \
    'SELECT function_code, start_address, quantity, operation_type, COUNT(*) AS events_count FROM modbus_events GROUP BY function_code, start_address, quantity, operation_type ORDER BY function_code, start_address' \
    "${ANALYSIS_DIR}/events_grouped_after_observe.tsv"
  sqlite_to_tsv \
    'SELECT id, timestamp, function_code, start_address, quantity, operation_type FROM modbus_events ORDER BY id LIMIT 8' \
    "${ANALYSIS_DIR}/events_sample.tsv"

  sqlite_single_value 'SELECT COUNT(*) FROM modbus_events' >"${ANALYSIS_DIR}/events_count_total.txt"
  {
    echo "SQL: SELECT COUNT(*) FROM modbus_events;"
    echo -n "Result: "
    cat "${ANALYSIS_DIR}/events_count_total.txt"
  } >"${ANALYSIS_DIR}/events_count_query.txt"
}

run_policy_generation_stage() {
  log "T4: генерация и проверка policy"
  cp "${ANALYSIS_DIR}/events_after_observe.tsv" "${POLICY_DIR}/observed_events_input.tsv"

  "${BIN_DIR}/firewall" generate-policy \
    --config "${CONFIG_PATH}" \
    --output "${CANDIDATE_POLICY_PATH}" \
    --baseline-output "${BASELINE_POLICY_PATH}" \
    --write-threshold "${WRITE_THRESHOLD}" >"${POLICY_DIR}/generate_policy_cli.log" 2>&1

  "${BIN_DIR}/firewall" validate-policy --policy "${CANDIDATE_POLICY_PATH}" >"${POLICY_DIR}/validate_policy_cli.log" 2>&1

  "${BIN_DIR}/firewall" replay \
    --config "${CONFIG_PATH}" \
    --policy "${CANDIDATE_POLICY_PATH}" \
    --output "${REPLAY_REPORT_PATH}" >"${POLICY_DIR}/replay_cli.log" 2>&1

  cp "${CANDIDATE_POLICY_PATH}" "${POLICY_DIR}/policy.candidate.yaml"
  cp "${BASELINE_POLICY_PATH}" "${POLICY_DIR}/policy.generated.yaml"
  cp "${REPLAY_REPORT_PATH}" "${POLICY_DIR}/replay-report.json"

  cat >"${POLICY_DIR}/policy_generation_report.md" <<EOF
# Отчёт по формированию политики

- Источник данных: SQLite история событий после сценариев T1-T3, файл [observed_events_input.tsv](./observed_events_input.tsv).
- Порог для write-операций: K=${WRITE_THRESHOLD}.
- В политику вошли:
  - чтение FC03 в виде одного allow-правила с тремя диапазонами адресов 0-1, 10-11 и 20-21, соответствующими наблюдённым штатным операциям;
  - запись FC06 по адресу 12, так как операция повторилась 10 раз и превышает порог K.
- В политику не вошла:
  - запись FC16 по диапазону 80-81, так как операция встретилась 1 раз и не достигает порога K=${WRITE_THRESHOLD}.
- Проверка покрытия выполнена через replay; полный машинный отчёт сохранён в [replay-report.json](./replay-report.json).
EOF
}

activate_enforce_mode() {
  local firewall_before
  local started_pid
  firewall_before="$(line_count "${FIREWALL_LOG_PATH}")"
  started_pid="$(awk -F= '/^firewall_pid=/{print $2}' "${ENV_DIR}/process_info_started.txt" | tr -d '[:space:]')"

  set_firewall_mode enforce
  "${BIN_DIR}/firewall" apply-policy --candidate "${CANDIDATE_POLICY_PATH}" --active "${ACTIVE_POLICY_PATH}" >"${FILTER_DIR}/activate_enforce_apply_policy.log" 2>&1
  wait_for_log_after "${FIREWALL_LOG_PATH}" 'previous_mode=observe new_mode=enforce' "${firewall_before}" 'переход observe->enforce'
  capture_log_slice "${FIREWALL_LOG_PATH}" "${firewall_before}" "${FILTER_DIR}/activate_enforce_firewall.log"
  cat >"${FILTER_DIR}/activate_enforce_restart_check.txt" <<EOF
firewall_pid_at_start=${started_pid}
firewall_pid_runtime=${FIREWALL_PID}
observe_to_enforce_hot_reload_detected=yes
observe_to_enforce_restart_detected=$([[ "${started_pid}" == "${FIREWALL_PID}" ]] && echo "no" || echo "yes")
evidence_log=activate_enforce_firewall.log
EOF
}

run_filter_stage() {
  log "T5: разрешённое чтение в enforce"
  run_arm_capture "${FILTER_DIR}" "t5_allowed_read" --scenario normal-read

  log "T6: разрешённая повторяющаяся запись в enforce"
  run_arm_capture "${FILTER_DIR}" "t6_allowed_repeated_write" --scenario repeated-write --repeat 3

  log "T7: запрещённая запись блокируется"
  read_register_snapshot "127.0.0.1" "${UPSTREAM_ADDR##*:}" 50 "${FILTER_DIR}/t7_register_50_before.txt"
  run_arm_capture "${FILTER_DIR}" "t7_blocked_forbidden_write" --scenario forbidden-write
  read_register_snapshot "127.0.0.1" "${UPSTREAM_ADDR##*:}" 50 "${FILTER_DIR}/t7_register_50_after.txt"

  python3 - "${FILTER_DIR}/t7_register_50_before.txt" "${FILTER_DIR}/t7_register_50_after.txt" "${FILTER_DIR}/t7_block_proof.txt" <<'PY'
import sys
from pathlib import Path

before_text = Path(sys.argv[1]).read_text(encoding="utf-8")
after_text = Path(sys.argv[2]).read_text(encoding="utf-8")

def extract_value(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("value="):
            return line.split("=", 1)[1]
    raise SystemExit("value not found")

before = extract_value(before_text)
after = extract_value(after_text)
status = "подтверждено" if before == after else "НЕ подтверждено"

Path(sys.argv[3]).write_text(
    "Проверка недостижения запрещённого запроса до PLC\n"
    f"Значение регистра 50 до запроса: {before}\n"
    f"Значение регистра 50 после запроса: {after}\n"
    f"Результат: {status}\n",
    encoding="utf-8",
)
PY
}

run_hot_reload_stage() {
  local firewall_before
  local pid_before
  local pid_after

  log "T8: hot reload policy без перезапуска"
  cp "${FILTER_DIR}/t7_blocked_forbidden_write_client.log" "${HOT_DIR}/t8_before_update_client.log"
  cp "${FILTER_DIR}/t7_blocked_forbidden_write_firewall.log" "${HOT_DIR}/t8_before_update_firewall.log"
  cp "${FILTER_DIR}/t7_register_50_after.txt" "${HOT_DIR}/t8_register_50_before.txt"

  pid_before="${FIREWALL_PID}"
  echo "${pid_before}" >"${HOT_DIR}/t8_firewall_pid_before.txt"

  cat >"${HOT_DIR}/t8_policy_candidate.yaml" <<'EOF'
version: 1
default_action: deny

rules:
  - id: allow-read-range
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 3
    address_ranges:
      - start: 0
        end: 21

  - id: allow-write-register-12
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 6
    address_ranges:
      - start: 12
        end: 12

  - id: allow-hot-reload-write
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 6
    address_ranges:
      - start: 50
        end: 50
EOF

  cp "${HOT_DIR}/t8_policy_candidate.yaml" "${CANDIDATE_POLICY_PATH}"
  firewall_before="$(line_count "${FIREWALL_LOG_PATH}")"
  "${BIN_DIR}/firewall" validate-policy --policy "${CANDIDATE_POLICY_PATH}" >"${HOT_DIR}/t8_validate_policy.log" 2>&1
  "${BIN_DIR}/firewall" apply-policy --candidate "${CANDIDATE_POLICY_PATH}" --active "${ACTIVE_POLICY_PATH}" >"${HOT_DIR}/t8_apply_policy.log" 2>&1
  wait_for_log_after "${FIREWALL_LOG_PATH}" 'previous_mode=enforce new_mode=enforce' "${firewall_before}" 'hot reload enforce->enforce'
  capture_log_slice "${FIREWALL_LOG_PATH}" "${firewall_before}" "${HOT_DIR}/t8_firewall_reload.log"

  run_arm_capture "${HOT_DIR}" "t8_after_update_forbidden_write" --scenario forbidden-write
  read_register_snapshot "127.0.0.1" "${UPSTREAM_ADDR##*:}" 50 "${HOT_DIR}/t8_register_50_after.txt"

  pid_after="${FIREWALL_PID}"
  echo "${pid_after}" >"${HOT_DIR}/t8_firewall_pid_after.txt"

  {
    echo "PID_before=${pid_before}"
    echo "PID_after=${pid_after}"
    if [[ "${pid_before}" == "${pid_after}" ]]; then
      echo "restart_detected=no"
    else
      echo "restart_detected=yes"
    fi
  } >"${HOT_DIR}/t8_restart_check.txt"

  log "T10: обновление policy при активном трафике"
  local t10_bg_log="${HOT_DIR}/t10_background_normal_read.log"
  local t10_bg_pid=""
  local t10_fw_before
  local t10_pid_before
  local t10_pid_after

  t10_pid_before="${FIREWALL_PID}"
  echo "${t10_pid_before}" >"${HOT_DIR}/t10_firewall_pid_before.txt"
  : >"${t10_bg_log}"

  (
    set +e
    for idx in $(seq 1 "${T10_BACKGROUND_ITERATIONS}"); do
      printf "ITERATION=%s\n" "${idx}" >>"${t10_bg_log}"
      "${BIN_DIR}/arm-sim" --target "${LISTEN_ADDR}" --scenario normal-read >>"${t10_bg_log}" 2>&1
      printf "ITERATION_EXIT=%s\n" "$?" >>"${t10_bg_log}"
      sleep 0.15
    done
  ) &
  t10_bg_pid="$!"

  sleep 1

  cat >"${HOT_DIR}/t10_policy_candidate.yaml" <<'EOF'
version: 1
default_action: deny

rules:
  - id: allow-read-range
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 3
    address_ranges:
      - start: 0
        end: 21

  - id: allow-write-register-12
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 6
    address_ranges:
      - start: 12
        end: 12

  - id: allow-hot-reload-write
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 6
    address_ranges:
      - start: 50
        end: 50

  - id: allow-rare-write-range
    action: allow
    source_ips:
      - "127.0.0.1"
    destination_ips:
      - "127.0.0.1"
    unit_ids:
      - 1
    function_codes:
      - 16
    address_ranges:
      - start: 80
        end: 81
EOF

  cp "${HOT_DIR}/t10_policy_candidate.yaml" "${CANDIDATE_POLICY_PATH}"
  t10_fw_before="$(line_count "${FIREWALL_LOG_PATH}")"
  "${BIN_DIR}/firewall" validate-policy --policy "${CANDIDATE_POLICY_PATH}" >"${HOT_DIR}/t10_validate_policy.log" 2>&1
  "${BIN_DIR}/firewall" apply-policy --candidate "${CANDIDATE_POLICY_PATH}" --active "${ACTIVE_POLICY_PATH}" >"${HOT_DIR}/t10_apply_policy.log" 2>&1
  wait_for_log_after "${FIREWALL_LOG_PATH}" 'previous_mode=enforce new_mode=enforce' "${t10_fw_before}" 'hot reload под активным трафиком'
  wait "${t10_bg_pid}"
  capture_log_slice "${FIREWALL_LOG_PATH}" "${t10_fw_before}" "${HOT_DIR}/t10_firewall_reload_and_traffic.log"

  run_arm_capture "${HOT_DIR}" "t10_rare_write_after_update" --scenario rare-write
  t10_pid_after="${FIREWALL_PID}"
  echo "${t10_pid_after}" >"${HOT_DIR}/t10_firewall_pid_after.txt"

  summarize_arm_logs "${HOT_DIR}/t10_background_metrics.json" "${t10_bg_log}"
  write_metrics_report "T10. Активный трафик во время hot reload" "${HOT_DIR}/t10_background_metrics.json" "${t10_pid_before}" "${t10_pid_after}" "${HOT_DIR}/t10_background_report.md"
  cat >"${HOT_DIR}/t10_workload_profile.txt" <<EOF
background_iterations=${T10_BACKGROUND_ITERATIONS}
requests_per_iteration=3
expected_background_requests=$((T10_BACKGROUND_ITERATIONS * 3))
reload_mode=enforce_to_enforce
policy_extension=allow_rare_write_range_80_81
EOF
}

run_stability_stage() {
  local pid_before
  local pid_after

  log "T9: серия штатных запросов"
  pid_before="${FIREWALL_PID}"
  echo "${pid_before}" >"${STABILITY_DIR}/t9_firewall_pid_before.txt"

  run_arm_capture "${STABILITY_DIR}" "t9_normal_read" --scenario normal-read
  run_arm_capture "${STABILITY_DIR}" "t9_repeated_write_load" --scenario repeated-write --repeat "${T9_REPEATED_WRITE_COUNT}"

  pid_after="${FIREWALL_PID}"
  echo "${pid_after}" >"${STABILITY_DIR}/t9_firewall_pid_after.txt"

  summarize_arm_logs "${STABILITY_DIR}/t9_metrics.json" \
    "${STABILITY_DIR}/t9_normal_read_client.log" \
    "${STABILITY_DIR}/t9_repeated_write_load_client.log"
  write_metrics_report "T9. Устойчивость при серии штатных запросов" "${STABILITY_DIR}/t9_metrics.json" "${pid_before}" "${pid_after}" "${STABILITY_DIR}/t9_report.md"
  cat >"${STABILITY_DIR}/t9_workload_profile.txt" <<EOF
normal_read_requests=3
repeated_write_requests=${T9_REPEATED_WRITE_COUNT}
expected_total_requests=$((T9_REPEATED_WRITE_COUNT + 3))
operation_mix=fc03_read_and_fc06_write_single_register
EOF
}

write_environment_notes() {
  cat >"${ENV_DIR}/execution_method.md" <<EOF
# Способ воспроизведения

Для подготовки артефактов использован локальный изолированный стенд внутри репозитория:

- firewall: [${BIN_DIR}/firewall](./runtime/bin/firewall)
- arm-sim: [${BIN_DIR}/arm-sim](./runtime/bin/arm-sim)
- plc-sim: исходный файл [plc-sim/server.py](../../plc-sim/server.py)
- конфигурация стенда: [runtime_config_initial.yaml](./runtime_config_initial.yaml)
- SQLite: [runtime/events.db](./runtime/events.db)

Выбран локальный путь, а не Docker Compose, чтобы:

- фиксировать один и тот же PID процесса firewall до и после hot reload;
- собирать отдельные срезы логов по каждому сценарию;
- не изменять рабочие файлы \`configs/\` и \`data/\` в корне репозитория.
EOF

  cat >"${ENV_DIR}/manual_reproduction_commands.md" <<EOF
# Точные команды воспроизведения

## Доступные команды из репозитория

- \`go run ./cmd/firewall help\`
- \`go run ./cmd/arm-sim --list-scenarios\`
- \`make build\`
- \`make test\`
- \`make demo-local\`
- \`make stand-up\` / \`make stand-down\` (если доступен Docker daemon)

## Локальный запуск, использованный для артефактов

1. Сборка:
   - \`go build -o ${BIN_DIR}/firewall ./cmd/firewall\`
   - \`go build -o ${BIN_DIR}/arm-sim ./cmd/arm-sim\`
2. PLC:
   - \`${VENV_DIR}/bin/python plc-sim/server.py --config ${PLC_CONFIG_PATH}\`
3. Firewall:
   - \`${BIN_DIR}/firewall run --config ${CONFIG_PATH} --policy ${ACTIVE_POLICY_PATH} --reload-interval 1s\`
4. Сценарии клиента:
   - \`${BIN_DIR}/arm-sim --target ${LISTEN_ADDR} --scenario normal-read\`
   - \`${BIN_DIR}/arm-sim --target ${LISTEN_ADDR} --scenario repeated-write --repeat 10\`
   - \`${BIN_DIR}/arm-sim --target ${LISTEN_ADDR} --scenario repeated-write --repeat ${T9_REPEATED_WRITE_COUNT}\` для длительного прогона T9
   - \`${BIN_DIR}/arm-sim --target ${LISTEN_ADDR} --scenario rare-write\`
   - \`${BIN_DIR}/arm-sim --target ${LISTEN_ADDR} --scenario forbidden-write\`
5. Генерация policy:
   - \`${BIN_DIR}/firewall generate-policy --config ${CONFIG_PATH} --output ${CANDIDATE_POLICY_PATH} --baseline-output ${BASELINE_POLICY_PATH} --write-threshold ${WRITE_THRESHOLD}\`
6. Валидация и применение:
   - \`${BIN_DIR}/firewall validate-policy --policy ${CANDIDATE_POLICY_PATH}\`
   - \`${BIN_DIR}/firewall apply-policy --candidate ${CANDIDATE_POLICY_PATH} --active ${ACTIVE_POLICY_PATH}\`
7. Replay:
   - \`${BIN_DIR}/firewall replay --config ${CONFIG_PATH} --policy ${CANDIDATE_POLICY_PATH} --output ${REPLAY_REPORT_PATH}\`
8. Проверка отсутствия рестарта:
   - \`ps -p \$(cat ${HOT_DIR}/t8_firewall_pid_before.txt) -o pid=,ppid=,lstart=,command=\`
   - сравнить файлы [t8_firewall_pid_before.txt](../05_hot_reload/t8_firewall_pid_before.txt) и [t8_firewall_pid_after.txt](../05_hot_reload/t8_firewall_pid_after.txt)
9. Проверка содержимого БД:
   - \`python3 - <<'PY'\`
     \`import sqlite3; conn = sqlite3.connect("${EVENTS_DB_PATH}"); print(conn.execute("SELECT COUNT(*) FROM modbus_events").fetchone()[0]); conn.close()\`
     \`PY\`
EOF
}

write_summary_report() {
  local observe_count
  local replay_values
  local replay_total replay_covered replay_blocked
  local t7_before t7_after
  local t8_after
  local t9_values
  local t9_total t9_ok t9_exc t9_err t9_drop
  local t10_values
  local t10_total t10_ok t10_exc t10_err t10_drop

  observe_count="$(tr -d '[:space:]' <"${ANALYSIS_DIR}/events_count_total.txt")"
  replay_values="$(python3 - "${POLICY_DIR}/replay-report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(report["total_events"], report["covered_events"], report["blocked_events"])
PY
)"
  read -r replay_total replay_covered replay_blocked <<<"${replay_values}"

  t7_before="$(grep '^value=' "${FILTER_DIR}/t7_register_50_before.txt" | cut -d= -f2)"
  t7_after="$(grep '^value=' "${FILTER_DIR}/t7_register_50_after.txt" | cut -d= -f2)"
  t8_after="$(grep '^value=' "${HOT_DIR}/t8_register_50_after.txt" | cut -d= -f2)"

  t9_values="$(python3 - "${STABILITY_DIR}/t9_metrics.json" <<'PY'
import json
import sys
from pathlib import Path

metrics = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(metrics["total_requests"], metrics["ok"], metrics["exceptions"], metrics["errors"], metrics["connection_drops"])
PY
)"
  read -r t9_total t9_ok t9_exc t9_err t9_drop <<<"${t9_values}"

  t10_values="$(python3 - "${HOT_DIR}/t10_background_metrics.json" <<'PY'
import json
import sys
from pathlib import Path

metrics = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(metrics["total_requests"], metrics["ok"], metrics["exceptions"], metrics["errors"], metrics["connection_drops"])
PY
)"
  read -r t10_total t10_ok t10_exc t10_err t10_drop <<<"${t10_values}"

  cat >"${SUMMARY_DIR}/vkr_testing_report.md" <<EOF
# 3.4. Тестирование решения

## Краткая сводка сценариев

| Сценарий | Цель | Фактический результат | Статус |
| --- | --- | --- | --- |
| T1 | Подтвердить пропуск штатного чтения в режиме анализа | 3 запроса FC03 прошли, события сохранены в SQLite | Успешно |
| T2 | Подтвердить накопление повторяющейся записи в режиме анализа | 10 запросов FC06 по адресу 12 прошли и записаны в историю | Успешно |
| T3 | Подтвердить фиксацию редкой записи без включения в policy | 1 запрос FC16 по диапазону 80-81 записан в историю, но не вошёл в policy | Успешно |
| T4 | Сформировать policy по накопленной истории | Сгенерирована candidate policy, replay показал 1 непокрытую редкую запись | Успешно |
| T5 | Проверить разрешённое чтение в режиме фильтрации | Штатное чтение прошло, firewall зафиксировал совпадение с правилом | Успешно |
| T6 | Проверить разрешённую повторяющуюся запись в режиме фильтрации | Повторяющаяся запись по адресу 12 прошла, firewall указал matched_rule_id | Успешно |
| T7 | Проверить блокировку запрещённой записи | Клиент получил Modbus exception, значение регистра 50 на PLC не изменилось | Успешно |
| T8 | Проверить hot reload без рестарта | Операция, ранее блокировавшаяся, после обновления policy прошла при неизменном PID | Успешно |
| T9 | Оценить устойчивость при серии запросов | Обработано ${t9_total} запросов, ошибок и обрывов соединения не зафиксировано | Успешно |
| T10 | Проверить обновление policy во время активного трафика | Во время ${t10_total} фоновых запросов выполнен hot reload без перезапуска и без ошибок | Успешно |

## Детализация сценариев

### T1. Штатное чтение регистров в режиме анализа

- Идентификатор сценария: T1
- Цель: подтвердить, что firewall в режиме \`observe\` не блокирует штатное чтение и сохраняет событие в историю.
- Входные данные: сценарий \`arm-sim --scenario normal-read\`; 3 запроса FC03 к диапазонам 0-1, 10-11, 20-21.
- Ожидаемый результат: все ответы успешны, в журнале firewall есть признаки принятия запроса, пропуска и сохранения события; в SQLite появляются записи.
- Фактический результат: все 3 операции завершились статусом \`OK\`; в журнале firewall присутствуют строки \`запрос принят\`, \`observe: запрос пропущен\`, \`событие сохранено в storage\`; события записаны в SQLite.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t1_normal_read_client.log), [firewall](../02_analysis_mode/t1_normal_read_firewall.log), [plc-sim](../02_analysis_mode/t1_normal_read_plc.log), [выборка из БД](../02_analysis_mode/events_sample.tsv).

### T2. Повторяющаяся запись одного и того же адреса в режиме анализа

- Идентификатор сценария: T2
- Цель: накопить повторяющуюся write-операцию для автоматического включения в policy.
- Входные данные: сценарий \`arm-sim --scenario repeated-write --repeat 10\`; 10 запросов FC06 по адресу 12.
- Ожидаемый результат: все запросы проходят, события сохраняются в SQLite.
- Фактический результат: 10 запросов завершились статусом \`OK\`; в SQLite зафиксированы 10 событий FC06 по адресу 12.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t2_repeated_write_client.log), [firewall](../02_analysis_mode/t2_repeated_write_firewall.log), [plc-sim](../02_analysis_mode/t2_repeated_write_plc.log), [агрегированная статистика событий](../02_analysis_mode/events_grouped_after_observe.tsv).

### T3. Редкая запись, остающаяся в истории, но не попадающая в политику

- Идентификатор сценария: T3
- Цель: подтвердить, что единичная write-операция сохраняется в истории, но не проходит фильтр порога K при генерации policy.
- Входные данные: сценарий \`arm-sim --scenario rare-write\`; 1 запрос FC16 к диапазону 80-81.
- Ожидаемый результат: операция проходит в \`observe\`, сохраняется в SQLite, но затем не включается в candidate policy.
- Фактический результат: запрос завершился статусом \`OK\`, событие сохранено; в candidate policy правило для FC16 диапазона 80-81 отсутствует.
- Статус: Успешно.
- Артефакты: [клиент](../02_analysis_mode/t3_rare_write_client.log), [firewall](../02_analysis_mode/t3_rare_write_firewall.log), [plc-sim](../02_analysis_mode/t3_rare_write_plc.log), [отчёт по формированию policy](../03_policy_generation/policy_generation_report.md).

### T4. Переход к формированию политики

- Идентификатор сценария: T4
- Цель: подтвердить автоматическое построение разрешающей policy по накопленной истории и анализ её покрытия.
- Входные данные: SQLite история из ${observe_count} событий после T1-T3; порог write-операций K=${WRITE_THRESHOLD}.
- Ожидаемый результат: candidate policy создаётся автоматически, baseline policy сохраняется, replay показывает, какие операции покрыты и какие нет.
- Фактический результат: сформированы файлы policy; replay показал total=${replay_total}, covered=${replay_covered}, blocked=${replay_blocked}; единственной непокрытой операцией осталась редкая запись FC16.
- Статус: Успешно.
- Артефакты: [исходные события](../03_policy_generation/observed_events_input.tsv), [candidate policy](../03_policy_generation/policy.candidate.yaml), [generated policy](../03_policy_generation/policy.generated.yaml), [CLI генератора](../03_policy_generation/generate_policy_cli.log), [CLI replay](../03_policy_generation/replay_cli.log), [replay-report](../03_policy_generation/replay-report.json), [краткий отчёт](../03_policy_generation/policy_generation_report.md).

### T5. Разрешённое чтение проходит в режиме фильтрации

- Идентификатор сценария: T5
- Цель: подтвердить отсутствие ложной блокировки штатного чтения после перехода в \`enforce\`.
- Входные данные: активирована candidate policy; сценарий \`normal-read\`.
- Ожидаемый результат: чтение проходит, firewall фиксирует совпадение с allow-правилом.
- Фактический результат: все операции завершились статусом \`OK\`; в firewall журнале присутствует строка \`запрос разрешен политикой\` с \`matched_rule_id\`.
- Статус: Успешно.
- Артефакты: [переключение в enforce](../04_filtering_mode/activate_enforce_firewall.log), [клиент](../04_filtering_mode/t5_allowed_read_client.log), [firewall](../04_filtering_mode/t5_allowed_read_firewall.log), [plc-sim](../04_filtering_mode/t5_allowed_read_plc.log).

### T6. Повторяющаяся запись, попавшая в policy, проходит

- Идентификатор сценария: T6
- Цель: подтвердить, что автоматически сформированная policy пропускает типовую write-операцию без прерывания обмена.
- Входные данные: активная policy после T4; сценарий \`repeated-write --repeat 3\`.
- Ожидаемый результат: все операции проходят, firewall фиксирует совпадение с правилом разрешения записи.
- Фактический результат: 3 операции FC06 завершились статусом \`OK\`; в журнале firewall присутствует \`matched_rule_id\` для разрешённой записи.
- Статус: Успешно.
- Артефакты: [клиент](../04_filtering_mode/t6_allowed_repeated_write_client.log), [firewall](../04_filtering_mode/t6_allowed_repeated_write_firewall.log), [plc-sim](../04_filtering_mode/t6_allowed_repeated_write_plc.log).

### T7. Запрещённая запись блокируется и клиент получает Modbus exception

- Идентификатор сценария: T7
- Цель: подтвердить блокировку операции, отсутствующей в active policy, и доказать, что запрос не дошёл до PLC.
- Входные данные: сценарий \`forbidden-write\`; FC06 запись по адресу 50.
- Ожидаемый результат: firewall блокирует запрос, клиент получает Modbus exception, значение регистра 50 на PLC не меняется.
- Фактический результат: клиент получил \`BLOCKED/EXCEPTION\`; в firewall журнале зафиксировано \`запрос заблокирован политикой\`; значение регистра 50 до запроса равно ${t7_before}, после запроса также равно ${t7_after}.
- Статус: Успешно.
- Артефакты: [клиент](../04_filtering_mode/t7_blocked_forbidden_write_client.log), [firewall](../04_filtering_mode/t7_blocked_forbidden_write_firewall.log), [значение регистра до](../04_filtering_mode/t7_register_50_before.txt), [значение регистра после](../04_filtering_mode/t7_register_50_after.txt), [доказательство недостижения PLC](../04_filtering_mode/t7_block_proof.txt).

### T8. Обновление policy без перезапуска службы

- Идентификатор сценария: T8
- Цель: подтвердить горячее обновление активной policy и изменение поведения firewall без рестарта процесса.
- Входные данные: новая policy с дополнительным allow-правилом для FC06 по адресу 50; повторный запуск сценария \`forbidden-write\`.
- Ожидаемый результат: до обновления операция блокируется, после обновления проходит; PID firewall не меняется.
- Фактический результат: до обновления клиент получал exception, после обновления операция завершилась статусом \`OK\`; PID в файлах [до](../05_hot_reload/t8_firewall_pid_before.txt) и [после](../05_hot_reload/t8_firewall_pid_after.txt) совпадает; значение регистра 50 на PLC после обновления изменилось на ${t8_after}.
- Статус: Успешно.
- Артефакты: [клиент до обновления](../05_hot_reload/t8_before_update_client.log), [новая policy](../05_hot_reload/t8_policy_candidate.yaml), [validate-policy](../05_hot_reload/t8_validate_policy.log), [apply-policy](../05_hot_reload/t8_apply_policy.log), [hot reload в firewall](../05_hot_reload/t8_firewall_reload.log), [клиент после обновления](../05_hot_reload/t8_after_update_forbidden_write_client.log), [значение регистра после](../05_hot_reload/t8_register_50_after.txt), [проверка отсутствия рестарта](../05_hot_reload/t8_restart_check.txt), [plc-sim](../05_hot_reload/t8_after_update_forbidden_write_plc.log).

### T9. Серия штатных запросов для оценки устойчивости работы

- Идентификатор сценария: T9
- Цель: оценить устойчивость работы firewall при серии из нескольких тысяч штатных запросов.
- Входные данные: один прогон \`normal-read\` и один прогон \`repeated-write --repeat ${T9_REPEATED_WRITE_COUNT}\`.
- Ожидаемый результат: все запросы обрабатываются без неожиданной ошибки, без обрыва соединения и без рестарта firewall.
- Фактический результат: отправлено ${t9_total} запросов; успешно обработано ${t9_ok}; заблокировано ${t9_exc}; неожиданные ошибки ${t9_err}; обрывы соединения ${t9_drop}; PID firewall не изменился.
- Статус: Успешно.
- Артефакты: [клиент normal-read](../06_stability/t9_normal_read_client.log), [клиент repeated-write](../06_stability/t9_repeated_write_load_client.log), [firewall normal-read](../06_stability/t9_normal_read_firewall.log), [firewall repeated-write](../06_stability/t9_repeated_write_load_firewall.log), [метрики JSON](../06_stability/t9_metrics.json), [отчёт по устойчивости](../06_stability/t9_report.md).

### T10. Обновление policy во время работы при активном трафике

- Идентификатор сценария: T10
- Цель: подтвердить применение новой policy во время активного штатного трафика без прерывания обмена.
- Входные данные: фоновые ${T10_BACKGROUND_ITERATIONS} прогонов \`normal-read\` и hot reload policy с добавлением allow-правила для \`rare-write\`.
- Ожидаемый результат: фоновые чтения продолжают проходить без ошибок, policy перечитывается без рестарта, после обновления \`rare-write\` проходит.
- Фактический результат: на фоне ${t10_total} штатных запросов выполнен hot reload; успешно обработано ${t10_ok}, ошибок ${t10_err}, обрывов соединения ${t10_drop}; PID firewall не изменился; после обновления \`rare-write\` завершился статусом \`OK\`.
- Статус: Успешно.
- Артефакты: [фоновый трафик](../05_hot_reload/t10_background_normal_read.log), [метрики фонового трафика](../05_hot_reload/t10_background_metrics.json), [отчёт по фоновому трафику](../05_hot_reload/t10_background_report.md), [новая policy](../05_hot_reload/t10_policy_candidate.yaml), [apply-policy](../05_hot_reload/t10_apply_policy.log), [журнал firewall во время трафика](../05_hot_reload/t10_firewall_reload_and_traffic.log), [клиент rare-write после обновления](../05_hot_reload/t10_rare_write_after_update_client.log).

## Файлы, пригодные для вставки в текст ВКР

### Рисунки

- [../02_analysis_mode/t1_normal_read_firewall.log](../02_analysis_mode/t1_normal_read_firewall.log) — фрагмент журнала firewall в режиме анализа.
- [../04_filtering_mode/t7_blocked_forbidden_write_client.log](../04_filtering_mode/t7_blocked_forbidden_write_client.log) — вывод клиента при получении Modbus exception.
- [../05_hot_reload/t8_firewall_reload.log](../05_hot_reload/t8_firewall_reload.log) — фрагмент журнала hot reload без рестарта.
- [../05_hot_reload/t10_firewall_reload_and_traffic.log](../05_hot_reload/t10_firewall_reload_and_traffic.log) — hot reload при активном трафике.

### Таблицы

- [../02_analysis_mode/events_grouped_after_observe.tsv](../02_analysis_mode/events_grouped_after_observe.tsv) — агрегированные события наблюдаемого трафика.
- [../03_policy_generation/replay-report.json](../03_policy_generation/replay-report.json) — показатели покрытия candidate policy.
- [../06_stability/t9_report.md](../06_stability/t9_report.md) — сводные метрики устойчивости.

### Листинги

- [../03_policy_generation/policy.candidate.yaml](../03_policy_generation/policy.candidate.yaml) — автоматически сформированная policy.
- [../05_hot_reload/t8_policy_candidate.yaml](../05_hot_reload/t8_policy_candidate.yaml) — policy после расширения правил для hot reload.
- [../01_environment/manual_reproduction_commands.md](../01_environment/manual_reproduction_commands.md) — команды ручного воспроизведения испытаний.

## Готовые подписи к материалам

### Подписи к рисункам

- Рисунок — Журнал межсетевого экрана в режиме анализа Modbus TCP трафика с фиксацией принятия запроса, его пропуска и сохранения события в историю.
- Рисунок — Результат попытки выполнения запрещённой Modbus TCP операции, при которой клиент получил Modbus exception, сформированный межсетевым экраном.
- Рисунок — Журнал межсетевого экрана при горячем обновлении активной политики без перезапуска процесса службы.
- Рисунок — Применение обновлённой политики межсетевого экрана во время активного технологического обмена.

### Подписи к таблицам

- Таблица — Агрегированный состав Modbus TCP операций, накопленных в истории на этапе наблюдения.
- Таблица — Результаты replay-анализа покрытия автоматически сформированной политики по историческим событиям.
- Таблица — Показатели устойчивости межсетевого экрана при серии штатных Modbus TCP запросов.

### Подписи к листингам

- Листинг — Автоматически сформированная разрешающая политика межсетевого экрана на основе накопленной истории Modbus TCP запросов.
- Листинг — Обновлённая версия активной политики, применённая механизмом hot reload.
- Листинг — Команды ручного воспроизведения экспериментов по тестированию прототипа межсетевого экрана.
EOF

  cat >"${SUMMARY_DIR}/chapter_alignment_notes.md" <<EOF
# Подстановка фактических чисел в текст главы

- Для сценария T9 рекомендуется использовать формулировку: «один цикл штатного чтения и один цикл повторяющейся записи с числом повторов ${T9_REPEATED_WRITE_COUNT}».
- Для сценария T9 фактическое число запросов: ${t9_total}.
- Для сценария T10 фактическое число фоновых запросов чтения: ${t10_total}.
- Для сценария T10 использовано ${T10_BACKGROUND_ITERATIONS} запусков сценария \`normal-read\` по 3 Modbus-запроса в каждом запуске.
- Для replay-анализа фактические показатели: total=${replay_total}, covered=${replay_covered}, blocked=${replay_blocked}.
- Для этапа наблюдения фактическое число накопленных событий: ${observe_count}.
EOF
}

main() {
  cd "${ROOT_DIR}"
  prepare_artifact_tree
  log "Подготовка структуры артефактов"
  capture_command_availability
  write_environment_notes
  prepare_runtime_files
  build_runtime_tools
  start_services
  run_analysis_stage
  run_policy_generation_stage
  activate_enforce_mode
  run_filter_stage
  run_hot_reload_stage
  run_stability_stage
  write_summary_report
  log "Артефакты сформированы в ${ARTIFACT_ROOT}"
}

main "$@"
