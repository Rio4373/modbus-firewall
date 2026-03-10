#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "SCENARIO 04: ENFORCE"
require_docker

set_firewall_mode "enforce"

compose exec -T firewall firewall apply-policy \
  --candidate ./configs/policy.candidate.yaml \
  --active ./configs/policy.yaml

sleep 2

normal_output="$(run_arm_scenario_with_retry normal-read)"
forbidden_output="$(run_arm_scenario_with_retry forbidden-write)"

printf "%s\n" "${normal_output}"
printf "%s\n" "${forbidden_output}"

if ! grep -q -- "-> OK" <<<"${normal_output}"; then
  printf "ОШИБКА: normal-read должен проходить в enforce режиме.\n" >&2
  exit 1
fi

if ! grep -q "BLOCKED/EXCEPTION" <<<"${forbidden_output}"; then
  printf "ОШИБКА: forbidden-write должен блокироваться в enforce режиме.\n" >&2
  exit 1
fi

printf "Ожидаемый результат: штатные операции проходят, запрещённая блокируется. Условие выполнено.\n"
