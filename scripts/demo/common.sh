#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

compose() {
  (cd "${ROOT_DIR}" && docker compose "$@")
}

require_docker() {
  if ! docker info >/dev/null 2>&1; then
    printf "ОШИБКА: Docker daemon недоступен. Запустите Docker Desktop/Engine и повторите команду.\n" >&2
    exit 1
  fi
}

set_firewall_mode() {
  local mode="$1"
  local config_path="${ROOT_DIR}/configs/config.yaml"

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
  ' "${config_path}" >"${config_path}.tmp"

  mv "${config_path}.tmp" "${config_path}"
}

ensure_dirs() {
  mkdir -p "${ROOT_DIR}/data" "${ROOT_DIR}/reports" "${ROOT_DIR}/configs"
}

sqlite_events_count() {
  local db_path="${ROOT_DIR}/data/events.db"

  if [[ ! -f "${db_path}" ]]; then
    echo 0
    return 0
  fi

  python3 - "${db_path}" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
conn = sqlite3.connect(path)
try:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM modbus_events")
    row = cursor.fetchone()
    print(int(row[0]) if row else 0)
finally:
    conn.close()
PY
}

run_arm_scenario_with_retry() {
  local scenario="$1"
  shift || true

  local attempts=20
  local output=""
  local idx

  for idx in $(seq 1 "${attempts}"); do
    if output="$(compose exec -T arm-sim arm-sim --target firewall:1502 --scenario "${scenario}" "$@" 2>&1)"; then
      printf "%s\n" "${output}"
      return 0
    fi
    sleep 1
  done

  printf "%s\n" "${output}" >&2
  return 1
}

print_header() {
  local title="$1"
  printf "\n========== %s ==========\n" "${title}"
}
