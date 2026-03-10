#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/00_prepare.sh"
"${SCRIPT_DIR}/01_observe.sh"
"${SCRIPT_DIR}/02_generate_policy.sh"
"${SCRIPT_DIR}/03_replay.sh"
"${SCRIPT_DIR}/04_enforce.sh"
"${SCRIPT_DIR}/05_hot_reload.sh"

echo
echo "DEMO COMPLETED: все сценарии успешно выполнены."
