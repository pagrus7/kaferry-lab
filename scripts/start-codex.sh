#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec codex --cd "$repo_root" \
  --model gpt-6.1-sol \
  -c 'model_reasoning_effort="high"' \
  -c 'agents.enabled=true' \
  -c 'agents.max_concurrent_threads_per_session=3' \
  -c 'agents.default_subagent_model="gpt-6.1-sol"' \
  -c 'agents.default_subagent_reasoning_effort="high"' \
  "$(cat "$repo_root/CODEX_PROMPT.md")"
