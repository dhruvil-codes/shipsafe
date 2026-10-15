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
install_go_binary() {
  name="$1"; url="$2"; archive="$3"; member="$4"
  if command -v "$name" >/dev/null 2>&1; then return 0; fi
  echo "[osint] installing ${name} from ${url}" >&2
  if ! curl -fsSL "$url" -o "/tmp/${archive}"; then
    echo "[osint] WARN: download failed for ${name}; stage will record ran=false" >&2
    return 0
  fi
  case "$archive" in
    *.zip)     unzip -q -o "/tmp/${archive}" -d /usr/local/bin "$member" 2>/dev/null || true ;;
    *.tar.gz)  tar -xzf "/tmp/${archive}" -C /usr/local/bin "$member" 2>/dev/null || true ;;
  esac
  chmod +x "/usr/local/bin/${member}" 2>/dev/null || true
  rm -f "/tmp/${archive}"
}

if [ "$(id -u)" = "0" ]; then
  BIN_DIR=/usr/local/bin
else
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  export PATH="$BIN_DIR:$PATH"
fi

install_go_binary subfinder \
  "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip" \
  "subfinder.zip" "subfinder"
install_go_binary httpx \
  "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip" \
  "httpx.zip" "httpx"
install_go_binary subzy \
  "https://github.com/PentestPad/subzy/releases/latest/download/subzy_linux_amd64.tar.gz" \
  "subzy.tar.gz" "subzy"

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
