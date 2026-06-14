#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_DIR="${DEMO_DIR:-$(mktemp -d /tmp/modbus-firewall-demo.XXXXXX)}"
VENV_DIR="${DEMO_DIR}/venv"
BIN_DIR="${DEMO_DIR}/bin"
ARTIFACT_DIR="${DEMO_DIR}/artifacts"
CONFIG_PATH="${ARTIFACT_DIR}/config.yaml"
ACTIVE_POLICY_PATH="${ARTIFACT_DIR}/policy.yaml"
CANDIDATE_POLICY_PATH="${ARTIFACT_DIR}/policy.candidate.yaml"
BASELINE_POLICY_PATH="${ARTIFACT_DIR}/policy.generated.yaml"
PLC_CONFIG_PATH="${ARTIFACT_DIR}/plc-config.json"
EVENTS_DB_PATH="${ARTIFACT_DIR}/events.db"
REPLAY_REPORT_PATH="${ARTIFACT_DIR}/replay-report.json"
FIREWALL_LOG_PATH="${ARTIFACT_DIR}/firewall.log"
PLC_LOG_PATH="${ARTIFACT_DIR}/plc-sim.log"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:16020}"
UPSTREAM_ADDR="${UPSTREAM_ADDR:-127.0.0.1:16021}"
UNIT_ID="${UNIT_ID:-1}"
WRITE_THRESHOLD="${WRITE_THRESHOLD:-2}"
FIREWALL_PID=""
PLC_PID=""

print_header() {
  printf "\n========== %s ==========\n" "$1"
}

cleanup() {
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

require_commands() {
  local missing=0
  local cmd

  for cmd in go python3 awk; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      printf "ОШИБКА: не найдена обязательная команда: %s\n" "${cmd}" >&2
      missing=1
    fi
  done

  if [[ "${missing}" -ne 0 ]]; then
    exit 1
  fi
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local name="$3"
  local attempt

  for attempt in $(seq 1 30); do
    if python3 - "${host}" "${port}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
    except OSError:
        raise SystemExit(1)
raise SystemExit(0)
PY
    then
      return 0
    fi
    sleep 1
  done

  printf "ОШИБКА: %s не поднялся на %s:%s\n" "${name}" "${host}" "${port}" >&2
  return 1
}

wait_for_log() {
  local file_path="$1"
  local pattern="$2"
  local description="$3"
  local attempt

  for attempt in $(seq 1 30); do
    if [[ -f "${file_path}" ]] && grep -q "${pattern}" "${file_path}"; then
      return 0
    fi
    sleep 1
  done

  printf "ОШИБКА: не дождались события в логах: %s\n" "${description}" >&2
  return 1
}

sqlite_query() {
  python3 - "${EVENTS_DB_PATH}" "$@" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
query = sys.argv[2]
params = sys.argv[3:]

conn = sqlite3.connect(path)
try:
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    for row in rows:
        print("\t".join(str(value) for value in row))
finally:
    conn.close()
PY
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

run_arm() {
  "${BIN_DIR}/arm-sim" --target "${LISTEN_ADDR}" --scenario "$@"
}

prepare_environment() {
  local upstream_host upstream_port

  print_header "PREPARE"
  require_commands

  mkdir -p "${BIN_DIR}" "${ARTIFACT_DIR}"
  upstream_host="${UPSTREAM_ADDR%:*}"
  upstream_port="${UPSTREAM_ADDR##*:}"

  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --disable-pip-version-check -q -r "${ROOT_DIR}/plc-sim/requirements.txt"

  go build -o "${BIN_DIR}/firewall" ./cmd/firewall
  go build -o "${BIN_DIR}/arm-sim" ./cmd/arm-sim

  cat > "${CONFIG_PATH}" <<EOF
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

  cat > "${ACTIVE_POLICY_PATH}" <<'EOF'
version: 1
default_action: deny
rules: []
EOF

  cat > "${PLC_CONFIG_PATH}" <<EOF
{
  "host": "${upstream_host}",
  "port": ${upstream_port},
  "unit_id": ${UNIT_ID},
  "register_count": 128,
  "holding_registers": {
    "0": 100,
    "1": 101,
    "10": 110,
    "11": 111,
    "20": 120,
    "21": 121,
    "50": 500
  },
  "input_registers": {
    "0": 200,
    "1": 201
  },
  "log_level": "INFO"
}
EOF

  printf "Рабочая директория демо: %s\n" "${DEMO_DIR}"
}

start_services() {
  local listen_host listen_port upstream_host upstream_port

  print_header "START SERVICES"
  listen_host="${LISTEN_ADDR%:*}"
  listen_port="${LISTEN_ADDR##*:}"
  upstream_host="${UPSTREAM_ADDR%:*}"
  upstream_port="${UPSTREAM_ADDR##*:}"

  "${VENV_DIR}/bin/python" "${ROOT_DIR}/plc-sim/server.py" --config "${PLC_CONFIG_PATH}" >"${PLC_LOG_PATH}" 2>&1 &
  PLC_PID="$!"
  wait_for_port "${upstream_host}" "${upstream_port}" "plc-sim"

  "${BIN_DIR}/firewall" run --config "${CONFIG_PATH}" --policy "${ACTIVE_POLICY_PATH}" --reload-interval 1s >"${FIREWALL_LOG_PATH}" 2>&1 &
  FIREWALL_PID="$!"
  wait_for_port "${listen_host}" "${listen_port}" "firewall"

  printf "plc-sim PID: %s\n" "${PLC_PID}"
  printf "firewall PID: %s\n" "${FIREWALL_PID}"
}

observe_stage() {
  local count

  print_header "1. OBSERVE"
  run_arm normal-read
  run_arm repeated-write --repeat 10
  run_arm rare-write

  count="$(sqlite_query 'SELECT COUNT(*) FROM modbus_events')"
  printf "Событий в SQLite: %s\n" "${count}"

  if [[ "${count}" -lt 14 ]]; then
    printf "ОШИБКА: ожидали минимум 14 событий после observe.\n" >&2
    exit 1
  fi
}

generate_policy_stage() {
  print_header "2. GENERATE POLICY"
  "${BIN_DIR}/firewall" generate-policy \
    --config "${CONFIG_PATH}" \
    --output "${CANDIDATE_POLICY_PATH}" \
    --baseline-output "${BASELINE_POLICY_PATH}" \
    --write-threshold "${WRITE_THRESHOLD}"

  "${BIN_DIR}/firewall" validate-policy --policy "${CANDIDATE_POLICY_PATH}"

  printf "Сгенерированная policy:\n"
  sed -n '1,220p' "${CANDIDATE_POLICY_PATH}"
}

replay_stage() {
  print_header "3. REPLAY"
  "${BIN_DIR}/firewall" replay \
    --config "${CONFIG_PATH}" \
    --policy "${CANDIDATE_POLICY_PATH}" \
    --output "${REPLAY_REPORT_PATH}"

  cat "${REPLAY_REPORT_PATH}"

  if ! grep -q '"blocked_events": 1' "${REPLAY_REPORT_PATH}"; then
    printf "ОШИБКА: ожидали минимум одну непокрытую операцию в replay.\n" >&2
    exit 1
  fi
}

activate_policy_stage() {
  print_header "4. APPLY POLICY"
  "${BIN_DIR}/firewall" apply-policy --candidate "${CANDIDATE_POLICY_PATH}" --active "${ACTIVE_POLICY_PATH}"
  set_firewall_mode enforce
  wait_for_log "${FIREWALL_LOG_PATH}" 'previous_mode=observe new_mode=enforce' 'переключение observe -> enforce'

  printf "Hot reload observe -> enforce подтверждён в логах.\n"
}

enforce_stage() {
  print_header "5. ENFORCE"
  run_arm normal-read

  local forbidden_output
  forbidden_output="$(run_arm forbidden-write)"
  printf "%s\n" "${forbidden_output}"

  if ! grep -q 'BLOCKED/EXCEPTION' <<<"${forbidden_output}"; then
    printf "ОШИБКА: forbidden-write должен блокироваться в enforce.\n" >&2
    exit 1
  fi

  if ! grep -q 'запрос заблокирован политикой' "${FIREWALL_LOG_PATH}"; then
    wait_for_log "${FIREWALL_LOG_PATH}" 'запрос заблокирован политикой' 'блокировка forbidden-write'
  fi

  printf "Последние события в SQLite:\n"
  sqlite_query 'SELECT function_code, start_address, quantity, operation_type FROM modbus_events ORDER BY id DESC LIMIT 5'
}

hot_reload_stage() {
  print_header "6. HOT RELOAD"

  cat > "${CANDIDATE_POLICY_PATH}" <<'EOF'
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

  "${BIN_DIR}/firewall" validate-policy --policy "${CANDIDATE_POLICY_PATH}"
  "${BIN_DIR}/firewall" apply-policy --candidate "${CANDIDATE_POLICY_PATH}" --active "${ACTIVE_POLICY_PATH}"
  sleep 2

  if ! kill -0 "${FIREWALL_PID}" >/dev/null 2>&1; then
    printf "ОШИБКА: firewall остановился во время hot reload.\n" >&2
    exit 1
  fi

  local forbidden_output
  forbidden_output="$(run_arm forbidden-write)"
  printf "%s\n" "${forbidden_output}"

  if grep -q 'BLOCKED/EXCEPTION' <<<"${forbidden_output}"; then
    printf "ОШИБКА: после hot reload forbidden-write должен проходить.\n" >&2
    exit 1
  fi

  if ! grep -q -- '-> OK' <<<"${forbidden_output}"; then
    printf "ОШИБКА: не удалось подтвердить успешное выполнение forbidden-write после hot reload.\n" >&2
    exit 1
  fi

  printf "Hot reload без остановки подтверждён. PID firewall: %s\n" "${FIREWALL_PID}"
}

show_artifacts() {
  print_header "ARTIFACTS"
  printf "Config: %s\n" "${CONFIG_PATH}"
  printf "Active policy: %s\n" "${ACTIVE_POLICY_PATH}"
  printf "Candidate policy: %s\n" "${CANDIDATE_POLICY_PATH}"
  printf "Baseline policy: %s\n" "${BASELINE_POLICY_PATH}"
  printf "SQLite DB: %s\n" "${EVENTS_DB_PATH}"
  printf "Replay report: %s\n" "${REPLAY_REPORT_PATH}"
  printf "Firewall log: %s\n" "${FIREWALL_LOG_PATH}"
  printf "PLC log: %s\n" "${PLC_LOG_PATH}"
}

main() {
  cd "${ROOT_DIR}"
  prepare_environment
  start_services
  observe_stage
  generate_policy_stage
  replay_stage
  activate_policy_stage
  enforce_stage
  hot_reload_stage
  show_artifacts
}

main "$@"
