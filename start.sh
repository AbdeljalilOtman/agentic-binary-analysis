#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "OPENROUTER_API_KEY is required" >&2
  exit 1
fi

python - <<'PY'
import sys
if sys.version_info < (3, 11):
    print("Python 3.11+ is required", file=sys.stderr)
    sys.exit(1)
PY

missing=0
for cmd in radare2 yara; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Warning: $cmd not found. Some tools will degrade." >&2
    missing=1
  fi
done

python -m agentic_binary_analysis.mcp.static_server &
python -m agentic_binary_analysis.mcp.dynamic_server &
python -m agentic_binary_analysis.mcp.pattern_server &
python -m agentic_binary_analysis.mcp.apk_server &

if [[ $# -gt 0 ]]; then
  exec python -m agentic_binary_analysis.cli "$@"
fi

wait
