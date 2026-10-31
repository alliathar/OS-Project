#!/usr/bin/env bash
#
# make_pdf.sh -- build results/findings.pdf from the generated results.
#
# Runs scripts/findings_pdf.py with the Python venv that setup.sh created (it
# has reportlab, which Ubuntu's system Python lacks). Run after run_all.sh and
# measure.sh.
#
# Usage: ./scripts/make_pdf.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/config/allocators.env"

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF missing. Run ./scripts/setup.sh first." >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$CONF"

PY="${REPORT_PYTHON:-}"
if [[ -z "$PY" || ! -x "$PY" ]]; then
    echo "ERROR: no Python with reportlab configured. Re-run ./scripts/setup.sh" >&2
    echo "       (it needs python3-venv and network access for pip)." >&2
    exit 1
fi

"$PY" "$ROOT/scripts/findings_pdf.py"
