#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "SCENARIO 02: GENERATE POLICY"
require_docker

compose exec -T firewall firewall generate-policy \
  --config ./configs/config.yaml \
  --output ./configs/policy.candidate.yaml \
  --baseline-output ./configs/policy.generated.yaml \
  --write-threshold 2

compose exec -T firewall firewall validate-policy --policy ./configs/policy.candidate.yaml

candidate_path="${ROOT_DIR}/configs/policy.candidate.yaml"
baseline_path="${ROOT_DIR}/configs/policy.generated.yaml"

if [[ ! -s "${candidate_path}" ]]; then
  printf "ОШИБКА: candidate policy не создана.\n" >&2
  exit 1
fi
if [[ ! -s "${baseline_path}" ]]; then
  printf "ОШИБКА: baseline policy не создана.\n" >&2
  exit 1
fi

rule_count="$(grep -c '^[[:space:]]- id:' "${candidate_path}" || true)"
printf "Сгенерировано правил: %s\n" "${rule_count}"

if [[ "${rule_count}" -lt 1 ]]; then
  printf "ОШИБКА: ожидали минимум 1 правило в candidate policy.\n" >&2
  exit 1
fi

printf "Ожидаемый результат: policy сгенерирована из событий observe и валидна. Условие выполнено.\n"
