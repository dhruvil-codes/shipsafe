#!/usr/bin/env python3
"""ShipSafe OSINT & attack-surface runner (stdlib only, zero simulation).

Orchestrates REAL open-source binaries inside the InstaBox Linux micro-VM:

  subfinder  (https://github.com/projectdiscovery/subfinder)
      passive subdomain enumeration  ->  subfinder -d <domain> -silent -json
  httpx      (https://github.com/projectdiscovery/httpx)
      live-host + technology probing ->  httpx -l <subs> -silent -json
                                         -tech-detect -status-code -title
  subzy      (https://github.com/PentestPad/subzy)
      subdomain-takeover detection   ->  subzy run --targets <subs> --hide_fails
  checkdmarc (https://github.com/domainaware/checkdmarc)
      SPF/DMARC validation           ->  checkdmarc -f json <domain>
  whois      (https://github.com/rfc1036/whois)
      registration / expiry          ->  whois <domain>

Usage:
    python3 osint_engine.py <TARGET_URL_OR_DOMAIN> <OUTDIR>

Always writes <OUTDIR>/osint_result.json shaped as a single ToolResult
(tool "osint-suite") plus <OUTDIR>/osint_result.sha256 — even on partial
failure. Evidence-first: a tool whose binary is missing or errors is
recorded with ran=false + error text and NEVER fabricates output. The
consolidated status is "passed" when at least one stage executed,
"failed" when nothing ran, and checksAttempted counts executed stages only.
Exit code 0 on success-or-partial; nonzero only when output could not be
written at all.
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

TOOL_VERSION = "1.0.0"
# Per-tool wall-clock budgets (the InstaBox exec ceiling is 10 minutes total).
TIMEOUTS = {
    "subfinder": 240,
    "httpx": 400,
    "subzy": 180,
    "checkdmarc": 60,
    "whois": 60,
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Preferred locations first: a pip-installed `httpx` stub can shadow the
# ProjectDiscovery binary on PATH, and `subzy` lives in ~/go/bin.
TOOL_SEARCH_DIRS = ["/usr/local/bin", os.path.expanduser("~/go/bin")]


def resolve_tool(name: str) -> str | None:
    """Absolute path of a tool binary, or None when not installed."""
    for directory in TOOL_SEARCH_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which(name)


def utcnow() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def extract_domain(target: str) -> str:
    """Accept a URL or bare domain; return the validated lowercase hostname."""
    candidate = target.strip()
    if "://" in candidate:
        candidate = urllib.parse.urlsplit(candidate).hostname or ""
    candidate = candidate.strip().strip(".").lower().rstrip(".")
    # Strip a trailing port if one survived (urlsplit already handles URLs).
    if candidate.count(":") == 1 and re.fullmatch(r"[a-z0-9.-]+:\d+", candidate):
        candidate = candidate.rsplit(":", 1)[0]
    if not candidate or not DOMAIN_RE.fullmatch(candidate):
        raise ValueError(f"not a valid domain: {target!r}")
    return candidate


def run_cmd(argv: list, timeout_s: int) -> dict:
    """Run a real binary; never raise. Returns a result record."""
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": (proc.stderr or "")[:2000],
            "latencyMs": int((time.monotonic() - started) * 1000),
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "latencyMs": int((time.monotonic() - started) * 1000),
            "missing": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"timed out after {timeout_s}s",
            "latencyMs": int((time.monotonic() - started) * 1000),
            "timeout": True,
        }
    except Exception as exc:  # noqa: BLE001 - record, never crash
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}"[:2000],
            "latencyMs": int((time.monotonic() - started) * 1000),
        }


def missing_section(tool: str, argv: list, detail: str) -> dict:
    return {
        "ran": False,
        "argv": argv,
        "returncode": None,
        "error": f"{tool} did not run: {detail}",
    }


# ------------------------------------------------------------- subfinder ---
def stage_subfinder(domain: str, tmpdir: str) -> tuple:
    out_path = os.path.join(tmpdir, "subdomains.txt")
    binary = resolve_tool("subfinder")
    argv = [binary or "subfinder", "-d", domain, "-silent", "-o", out_path]
    if binary is None:
        return missing_section("subfinder", argv, "binary not installed"), []
    res = run_cmd(argv, TIMEOUTS["subfinder"])
    subdomains: list = []
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            subdomains = sorted({ln.strip().lower() for ln in fh if ln.strip()})
    elif res["stdout"]:
        # Older/newer flag drift: fall back to stdout lines, whatever they are.
        subdomains = sorted(
            {ln.strip().lower() for ln in res["stdout"].splitlines() if ln.strip()}
        )
    section = {
        "ran": True,
        "argv": argv,
        "returncode": res["returncode"],
        "subdomains": subdomains,
        "count": len(subdomains),
        "latencyMs": res["latencyMs"],
    }
    if not res["ok"]:
        section["error"] = res["stderr"] or "subfinder exited nonzero"
    return section, subdomains


# ------------------------------------------------------------------ httpx ---
def stage_httpx(subdomains: list, tmpdir: str) -> dict:
    total = len(subdomains)
    capped = subdomains[:MAX_OSINT_TARGETS]
    targets_path = os.path.join(tmpdir, "httpx_targets.txt")
    with open(targets_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(capped) + ("\n" if capped else ""))
    binary = resolve_tool("httpx")
    argv = [
        binary or "httpx", "-l", targets_path, "-silent", "-json",
        "-tech-detect", "-status-code", "-title",
        "-timeout", "10", "-retries", "1",
    ]
    if binary is None:
        return missing_section("httpx", argv, "binary not installed")
    res = run_cmd(argv, TIMEOUTS["httpx"])
    hosts: list = []
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            hosts.append(obj)
    section: dict = {
        "ran": True,
        "argv": argv,
        "returncode": res["returncode"],
        "hosts": hosts,
        "count": len(hosts),
        "totalSubdomains": total,
        "truncated": total > len(capped),
        "latencyMs": res["latencyMs"],
    }
    if not res["ok"] and not hosts:
        section["error"] = res["stderr"] or "httpx exited nonzero with no JSON output"
    elif not res["ok"]:
        section["note"] = f"httpx exited {res['returncode']} but yielded {len(hosts)} host records"
    return section


# ------------------------------------------------------------------ subzy ---
def stage_subzy(subdomains: list, tmpdir: str) -> dict:
    total = len(subdomains)
    capped = subdomains[:MAX_OSINT_TARGETS]
    targets_path = os.path.join(tmpdir, "subzy_targets.txt")
    with open(targets_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(capped) + ("\n" if capped else ""))
    binary = resolve_tool("subzy")
    argv = [binary or "subzy", "run", "--targets", targets_path, "--hide_fails"]
    if binary is None:
        return missing_section("subzy", argv, "binary not installed")
    res = run_cmd(argv, TIMEOUTS["subzy"])
    raw = (res["stdout"] or "").strip()
    results: list = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("subdomain"):
                results.append(obj)
    section: dict = {
        "ran": True,
        "argv": argv,
        "returncode": res["returncode"],
        "results": results,
        "raw": raw[:8000],
        "totalSubdomains": total,
        "truncated": total > len(capped),
        "latencyMs": res["latencyMs"],
    }
    if not res["ok"]:
        section["error"] = res["stderr"] or "subzy exited nonzero"
    return section


# -------------------------------------------------------------- checkdmarc ---
def stage_checkdmarc(domain: str) -> dict:
    binary = resolve_tool("checkdmarc")
    argv = [binary or "checkdmarc", "-f", "json", domain]
    if binary is None:
        return missing_section("checkdmarc", argv, "binary not installed")
    res = run_cmd(argv, TIMEOUTS["checkdmarc"])
    parsed = None
    text = (res["stdout"] or "").strip()
    if text:
        try:
            obj = json.loads(text)
            parsed = obj if isinstance(obj, dict) else {"output": obj}
        except json.JSONDecodeError:
            # Flag drift across versions: retry with the bare domain form and
            # parse whatever comes back as JSON.
            retry = run_cmd([binary or "checkdmarc", domain], TIMEOUTS["checkdmarc"])
            try:
                obj = json.loads((retry["stdout"] or "").strip())
                parsed = obj if isinstance(obj, dict) else {"output": obj}
                text = (retry["stdout"] or "").strip()
            except (json.JSONDecodeError, ValueError):
                parsed = None
    section: dict = {
        "ran": True,
        "argv": argv,
        "returncode": res["returncode"],
        "parsed": parsed,
        "raw": text[:8000],
        "latencyMs": res["latencyMs"],
    }
    if parsed is None:
        section["error"] = (res["stderr"] or "checkdmarc produced no parseable JSON")[:2000]
    elif not res["ok"]:
        section["note"] = f"checkdmarc exited {res['returncode']} but yielded parsed output"
    return section


# ------------------------------------------------------------------ whois ---
WHOIS_PATTERNS = {
    "registrar": re.compile(r"^\s*registrar:\s*(.+)$", re.I | re.M),
    "creationDate": re.compile(
        r"^\s*(creation date|created|registered on|registration time):\s*(.+)$", re.I | re.M
    ),
    "expiryDate": re.compile(
        r"^\s*(registry expiry date|registrar registration expiration date|"
        r"expiry date|expires|expiration date|expire|paid-till):\s*(.+)$",
        re.I | re.M,
    ),
}

# Upper bound on hosts fed to httpx/subzy: certificate-transparency sources
# can return tens of thousands of (often bogus) names for large domains.
# The full count is preserved in evidence (`totalSubdomains`, `truncated`).
MAX_OSINT_TARGETS = 500


def stage_whois(domain: str) -> dict:
    binary = resolve_tool("whois")
    argv = [binary or "whois", domain]
    if binary is None:
        return missing_section("whois", argv, "binary not installed")
    res = run_cmd(argv, TIMEOUTS["whois"])
    text = res["stdout"] or ""
    section: dict = {
        "ran": True,
        "argv": argv,
        "returncode": res["returncode"],
        "latencyMs": res["latencyMs"],
    }
    if not res["ok"] and not text:
        section["error"] = res["stderr"] or "whois exited nonzero with no output"
        return section
    section["text"] = text[:4000]
    for key, pattern in WHOIS_PATTERNS.items():
        match = pattern.search(text)
        # Single-group (registrar) and two-group (dated) patterns alike:
        # the value is always the last group.
        section[key] = match.groups()[-1].strip()[:200] if match else None
    expiry = section.get("expiryDate")
    days: int | None = None
    if isinstance(expiry, str):
        for candidate in (expiry, expiry.split("T")[0]):
            try:
                dt = datetime.datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                break
            except ValueError:
                dt = None
        if dt is None:
            try:
                dt = datetime.datetime.strptime(expiry[:10], "%Y-%m-%d")
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                dt = None
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
    section["daysUntilExpiry"] = days
    return section


# ------------------------------------------------------------- orchestrate ---
def run_osint(target: str, tmpdir: str) -> dict:
    started_at = utcnow()
    t0 = time.monotonic()
    domain = extract_domain(target)
    sub_section, subdomains = stage_subfinder(domain, tmpdir)
    sections = {
        "domain": domain,
        "subfinder": sub_section,
        "httpx": stage_httpx(subdomains, tmpdir),
        "subzy": stage_subzy(subdomains, tmpdir),
        "checkdmarc": stage_checkdmarc(domain),
        "whois": stage_whois(domain),
    }
    executed = sum(1 for key in ("subfinder", "httpx", "subzy", "checkdmarc", "whois")
                   if isinstance(sections[key], dict) and sections[key].get("ran") is True)
    status = "passed" if executed > 0 else "failed"
    result = {
        "tool": "osint-suite",
        "toolVersion": TOOL_VERSION,
        "status": status,
        "startedAt": started_at,
        "endedAt": utcnow(),
        "durationMs": int((time.monotonic() - t0) * 1000),
        "checksAttempted": executed,
        "evidence": sections,
    }
    if status == "failed":
        result["error"] = "no OSINT stage executed (binaries missing or all errored)"
    return result


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: osint_engine.py <TARGET_URL_OR_DOMAIN> <OUTDIR>", file=sys.stderr)
        return 2
    target, outdir = argv[1], argv[2]
    os.makedirs(outdir, exist_ok=True)
    tmpdir = os.path.join(outdir, ".osint_tmp")
    os.makedirs(tmpdir, exist_ok=True)
    try:
        result = run_osint(target, tmpdir)
    except ValueError as exc:
        # Invalid target: still emit a failed ToolResult (never a crash).
        now = utcnow()
        result = {
            "tool": "osint-suite",
            "toolVersion": TOOL_VERSION,
            "status": "failed",
            "startedAt": now,
            "endedAt": now,
            "durationMs": 0,
            "checksAttempted": 0,
            "evidence": {"target": target, "error": str(exc)},
            "error": str(exc),
        }
    out_path = os.path.join(outdir, "osint_result.json")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        digest = hashlib.sha256(
            json.dumps(result, sort_keys=True).encode()
        ).hexdigest()
        with open(os.path.join(outdir, "osint_result.sha256"), "w", encoding="utf-8") as fh:
            fh.write(f"{digest}  osint_result.json\n")
    except Exception as exc:  # noqa: BLE001 - runner itself failed
        print(f"osint-engine: failed to write output: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
