#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "DEMO PREPARE"
require_docker

ensure_dirs
set_firewall_mode "observe"

rm -f "${ROOT_DIR}/data/events.db"
rm -f "${ROOT_DIR}/configs/policy.candidate.yaml"
rm -f "${ROOT_DIR}/configs/policy.generated.yaml"
rm -f "${ROOT_DIR}/configs/policy.yaml"
rm -f "${ROOT_DIR}/configs/policy.yaml.approved"
rm -f "${ROOT_DIR}/reports/replay-report.json"

compose down --remove-orphans >/dev/null 2>&1 || true
compose up --build -d

printf "Подготовка завершена: стенд запущен в режиме observe, данные демо очищены.\n"
