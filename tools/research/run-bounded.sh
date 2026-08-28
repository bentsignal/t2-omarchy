#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "usage: $0 COMMAND [ARG ...]" >&2
  exit 2
fi

research_memory_max=${T2_RESEARCH_MEMORY_MAX:-1G}
research_swap_max=${T2_RESEARCH_SWAP_MAX:-256M}
research_tasks_max=${T2_RESEARCH_TASKS_MAX:-64}

exec systemd-run --user --scope --quiet \
  -p "MemoryMax=${research_memory_max}" \
  -p "MemorySwapMax=${research_swap_max}" \
  -p "TasksMax=${research_tasks_max}" \
  -- "$@"
