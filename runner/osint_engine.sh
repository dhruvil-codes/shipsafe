#!/usr/bin/env bash
# ShipSafe OSINT engine entrypoint (runs inside the InstaBox Linux micro-VM).
#
# Installs the official open-source OSINT toolchain when missing, then runs
# osint_engine.py against <TARGET_URL_OR_DOMAIN> and writes
# <OUTDIR>/osint_result.json (+ sha256 checksum).
#
# Tools (official upstreams):
#   subfinder  https://github.com/projectdiscovery/subfinder
#   httpx      https://github.com/projectdiscovery/httpx
#   subzy      https://github.com/PentestPad/subzy
#   checkdmarc https://github.com/domainaware/checkdmarc
#   whois      https://github.com/rfc1036/whois (+ dnsutils for dig)
#
# Usage: osint_engine.sh <TARGET_URL_OR_DOMAIN> <OUTDIR>
# Exit 0 when output was written (even on partial tool failure); nonzero
# only when the runner itself could not write output.
set -u

TARGET="${1:-}"
OUTDIR="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$TARGET" ] || [ -z "$OUTDIR" ]; then
  echo "usage: osint_engine.sh <TARGET_URL_OR_DOMAIN> <OUTDIR>" >&2
  exit 2
fi

# --- 1. Go binaries (ProjectDiscovery + subzy): install when missing --------
if [ "$(id -u)" = "0" ]; then
  BIN_DIR=/usr/local/bin
else
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  export PATH="$BIN_DIR:$PATH"
fi

# NOTE: ProjectDiscovery release zips use versioned asset names
# (subfinder_2.17.0_linux_amd64.zip), so resolve via the GitHub API.
# PentestPad/subzy publishes no release artifacts: install via `go install`.
install_pd_binary() {
  repo="$1"; name="$2"
  if command -v "$name" >/dev/null 2>&1 && [ "$(command -v "$name")" != "$HOME/.local/bin/$name" ]; then return 0; fi
  echo "[osint] installing ${name} from ${repo}" >&2
  asset_url="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
    | grep -o "\"browser_download_url\": *\"[^\"]*linux_amd64[^\"]*\"\"" \
    | head -1 | cut -d'"' -f4)" || true
  if [ -z "$asset_url" ]; then
    echo "[osint] WARN: could not resolve ${name} release; stage will record ran=false" >&2
    return 0
  fi
  if ! curl -fsSL "$asset_url" -o "/tmp/${name}.zip"; then
    echo "[osint] WARN: download failed for ${name}; stage will record ran=false" >&2
    return 0
  fi
  if [ "$(id -u)" = "0" ]; then
    unzip -q -o "/tmp/${name}.zip" -d /usr/local/bin "$name" 2>/dev/null || true
  else
    unzip -q -o "/tmp/${name}.zip" -d "$BIN_DIR" "$name" 2>/dev/null || true
  fi
  chmod +x "$BIN_DIR/${name}" 2>/dev/null || true
  rm -f "/tmp/${name}.zip"
}

install_pd_binary projectdiscovery/subfinder subfinder
install_pd_binary projectdiscovery/httpx httpx

if ! command -v subzy >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    echo "[osint] installing subzy via go install" >&2
    go install github.com/PentestPad/subzy@latest 2>/dev/null || \
      echo "[osint] WARN: go install failed; subzy stage will record ran=false" >&2
    export PATH="$HOME/go/bin:$PATH"
  else
    echo "[osint] WARN: no go toolchain; subzy stage will record ran=false" >&2
  fi
fi

# --- 2. checkdmarc (Python) ---------------------------------------------------
if ! command -v checkdmarc >/dev/null 2>&1; then
  echo "[osint] installing checkdmarc via pip" >&2
  pip install --quiet checkdmarc dnspython 2>/dev/null || \
    pip3 install --quiet checkdmarc dnspython 2>/dev/null || \
    echo "[osint] WARN: pip install failed; checkdmarc stage will record ran=false" >&2
fi

# --- 3. whois + dnsutils (apt) -------------------------------------------------
if ! command -v whois >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    echo "[osint] installing whois + dnsutils via apt" >&2
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y whois dnsutils >/dev/null 2>&1 || \
      echo "[osint] WARN: apt install failed; whois stage will record ran=false" >&2
  else
    echo "[osint] WARN: whois missing and no root apt; stage will record ran=false" >&2
  fi
fi

# --- 4. Run the orchestrator (real binaries only, no simulation) --------------
mkdir -p "$OUTDIR"
python3 "$SCRIPT_DIR/osint_engine.py" "$TARGET" "$OUTDIR"
rc=$?
if [ $rc -ne 0 ]; then
  echo "[osint] runner failed (exit $rc)" >&2
fi
exit $rc
