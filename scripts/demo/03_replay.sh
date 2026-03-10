#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "SCENARIO 03: REPLAY"
require_docker

compose exec -T firewall firewall replay \
  --config ./configs/config.yaml \
  --policy ./configs/policy.candidate.yaml \
  --output ./reports/replay-report.json

report_path="${ROOT_DIR}/reports/replay-report.json"
if [[ ! -s "${report_path}" ]]; then
  printf "ОШИБКА: replay report не создан.\n" >&2
  exit 1
fi

python3 - "${report_path}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    report = json.load(fh)

total = int(report.get("total_events", 0))
covered = int(report.get("covered_events", 0))
blocked = int(report.get("blocked_events", 0))

print(f"Replay report: total={total} covered={covered} blocked={blocked}")

if total <= 0:
    raise SystemExit("ОШИБКА: total_events должен быть > 0")
if blocked < 1:
    raise SystemExit("ОШИБКА: для демо ожидается минимум 1 blocked event")
PY

printf "Ожидаемый результат: replay показывает покрытие и непокрытые операции. Условие выполнено.\n"
