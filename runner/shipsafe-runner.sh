#!/usr/bin/env bash
# shipsafe-runner.sh — In-VM security runner entrypoint.
#
# Usage: shipsafe-runner.sh <TARGET_URL> <OUTDIR>
#
# Calls scanner.py, handles missing tools gracefully, and ALWAYS writes
# $OUTDIR/scan_result.json plus a SHA-256 checksum file.
# Exit 0 even on partial failure (failed tools are recorded, never invented).
# Nonzero exit only when the runner itself could not produce output.
set -u

TARGET_URL="${1:-}"
OUTDIR="${2:-}"

if [ -z "$TARGET_URL" ] || [ -z "$OUTDIR" ]; then
  echo "usage: shipsafe-runner.sh <TARGET_URL> <OUTDIR>" >&2
  exit 2
fi

mkdir -p "$OUTDIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/scanner.py"

# Prefer python3, fall back to python.
PYBIN=""
if command -v python3 >/dev/null 2>&1; then
  PYBIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYBIN="python"
fi

if [ -z "$PYBIN" ]; then
  echo "shipsafe-runner: no python interpreter found; writing failure result" >&2
  TS="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  printf '{"target":%s,"scannedAt":"%s","tools":[],"error":"no python interpreter"}' \
    "$(printf '%s' "$TARGET_URL" | sed 's/\\/\\\\/g; s/"/\\"/g')" "$TS" > "$OUTDIR/scan_result.json"
  (cd "$OUTDIR" && sha256sum scan_result.json > scan_result.sha256 2>/dev/null || shasum -a 256 scan_result.json > scan_result.sha256)
  exit 0
fi

if [ ! -f "$SCANNER" ]; then
  echo "shipsafe-runner: scanner.py not found at $SCANNER" >&2
  exit 1
fi

# Run the scanner; never propagate tool failures as runner failure.
"$PYBIN" "$SCANNER" "$TARGET_URL" "$OUTDIR"
RC=$?

if [ $RC -ne 0 ]; then
  echo "shipsafe-runner: scanner exited $RC (partial failure recorded)" >&2
fi

# Guarantee output files exist even if scanner.py crashed before writing.
if [ ! -f "$OUTDIR/scan_result.json" ]; then
  echo "shipsafe-runner: scanner produced no output; writing failure stub" >&2
  TS="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  printf '{"target":"%s","scannedAt":"%s","tools":[],"error":"scanner produced no output"}' \
    "$TARGET_URL" "$TS" > "$OUTDIR/scan_result.json"
fi

if [ ! -f "$OUTDIR/scan_result.sha256" ]; then
  (cd "$OUTDIR" && sha256sum scan_result.json > scan_result.sha256 2>/dev/null || shasum -a 256 scan_result.json > scan_result.sha256)
fi

# Exit 0 even on partial failure: failed tools are data, not a runner crash.
exit 0
