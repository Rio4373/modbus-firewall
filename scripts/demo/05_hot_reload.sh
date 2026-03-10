#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

print_header "SCENARIO 05: HOT RELOAD"
require_docker

firewall_id_before="$(compose ps -q firewall)"

cat > "${ROOT_DIR}/configs/policy.candidate.yaml" <<'YAML'
version: 1
default_action: deny

rules:
  - id: allow-read-range
    action: allow
    source_ips:
      - "10.10.0.2"
    destination_ips:
      - "10.10.0.3"
    unit_ids:
      - 1
    function_codes:
      - 3
      - 4
    address_ranges:
      - start: 0
        end: 200

  - id: allow-hot-reload-write
    action: allow
    source_ips:
      - "10.10.0.2"
    destination_ips:
      - "10.10.0.3"
    unit_ids:
      - 1
    function_codes:
      - 6
    address_ranges:
      - start: 1000
        end: 1000
YAML

compose exec -T firewall firewall validate-policy --policy ./configs/policy.candidate.yaml
compose exec -T firewall firewall apply-policy \
  --candidate ./configs/policy.candidate.yaml \
  --active ./configs/policy.yaml

sleep 2

firewall_id_after="$(compose ps -q firewall)"
if [[ -z "${firewall_id_before}" || -z "${firewall_id_after}" || "${firewall_id_before}" != "${firewall_id_after}" ]]; then
  printf "ОШИБКА: firewall контейнер перезапущен, ожидали hot reload без остановки.\n" >&2
  exit 1
fi

forbidden_output="$(run_arm_scenario_with_retry forbidden-write)"
printf "%s\n" "${forbidden_output}"

if grep -q "BLOCKED/EXCEPTION" <<<"${forbidden_output}"; then
  printf "ОШИБКА: после hot reload forbidden-write должен быть разрешён.\n" >&2
  exit 1
fi
if ! grep -q -- "-> OK" <<<"${forbidden_output}"; then
  printf "ОШИБКА: не удалось подтвердить успешное выполнение forbidden-write после hot reload.\n" >&2
  exit 1
fi

printf "Ожидаемый результат: новая policy подхвачена без рестарта firewall, поведение изменилось. Условие выполнено.\n"
