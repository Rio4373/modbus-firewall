#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "SCENARIO 01: OBSERVE"
require_docker

normal_output="$(run_arm_scenario_with_retry normal-read)"
repeated_output="$(run_arm_scenario_with_retry repeated-write --repeat 10)"
rare_output="$(run_arm_scenario_with_retry rare-write)"

printf "%s\n" "${normal_output}"
printf "%s\n" "${repeated_output}"
printf "%s\n" "${rare_output}"

count="$(sqlite_events_count)"
printf "Событий в SQLite: %s\n" "${count}"

if [[ "${count}" -lt 14 ]]; then
  printf "ОШИБКА: ожидали минимум 14 событий (3 read + 10 repeated write + 1 rare write).\n" >&2
  exit 1
fi

printf "Ожидаемый результат: observe пишет события в SQLite. Условие выполнено.\n"
