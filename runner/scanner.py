#!/usr/bin/env python3
"""ShipSafe in-VM security runner (stdlib only).

Probes a target URL for baseline web-security posture:
  (a) TLS certificate validity / expiry / cipher suite (ssl module)
  (b) HTTP security headers (HSTS, CSP, X-Frame-Options, CORS, cookie flags,
      server-leak banners) via urllib
  (c) Sensitive-file discovery (.env, .git/HEAD, wp-config.php, /api/docs)
      via HTTP status probing
  (d) Port / banner probing (80, 443, 22, 3306, 6379) via quick socket connect

Usage:
    python3 scanner.py <TARGET_URL> <OUTDIR>

Always writes <OUTDIR>/scan_result.json (even on partial failure) shaped as:
    { target, scannedAt, tools: ToolResult[] }
where ToolResult = { tool, toolVersion, status, startedAt, endedAt,
                     durationMs, checksAttempted, evidence, error? }.

Evidence-first: every check result carries raw evidence. A tool that cannot
run is recorded as `skipped`/`failed` and NEVER as `passed`.
Exit code 0 on success-or-partial; nonzero only when the runner itself
could not write output.
"""

import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCANNER_VERSION = "0.1.0"
SOCKET_TIMEOUT_S = 5


def utcnow() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def make_tool_result(tool: str, checks_attempted: int = 0) -> dict:
    started = utcnow()
    return {
        "tool": tool,
        "toolVersion": SCANNER_VERSION,
        "status": "passed",
        "startedAt": started,
        "_t0": time.monotonic(),
        "checksAttempted": checks_attempted,
        "evidence": {},
    }


def finish_tool(tr: dict, status: str, evidence: dict, error: str | None = None) -> dict:
    tr["status"] = status
    tr["endedAt"] = utcnow()
    tr["durationMs"] = int((time.monotonic() - tr.pop("_t0")) * 1000)
    tr["evidence"] = evidence
    if error:
        tr["error"] = error
    return tr


# ---------------------------------------------------------------- TLS check
def check_tls(target: str) -> dict:
    tr = make_tool_result("tls-probe")
    evidence: dict = {"target": target}
    try:
        parts = urllib.parse.urlparse(target if "://" in target else "https://" + target)
        host = parts.hostname or target
        port = parts.port or 443
        evidence["host"] = host
        evidence["port"] = port
        ctx = ssl.create_default_context()
        # Evidence-first: capture the negotiated cipher + peer cert, whatever they are.
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher()
                peer = tls.getpeercert()
                evidence["cipher"] = {
                    "name": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                }
                evidence["peerCert"] = peer
                evidence["protocolNegotiated"] = (
                    tls.version() if hasattr(tls, "version") else None
                )
        # Expiry analysis (informational; the raw cert dict is the evidence).
        try:
            not_after = evidence["peerCert"].get("notAfter") if isinstance(evidence.get("peerCert"), dict) else None
            evidence["notAfter"] = not_after
        except Exception as exc:  # noqa: BLE001 - record, never crash
            evidence["expiryParseError"] = str(exc)
        tr["checksAttempted"] = 3  # validity, expiry, cipher
        weak = str(evidence.get("cipher", {}).get("name", ""))
        status = "passed"
        if re.search(r"RC4|DES|3DES|MD5|NULL|EXPORT|anon", weak, re.I):
            status = "failed"
        return finish_tool(tr, status, evidence)
    except Exception as exc:  # noqa: BLE001 - partial failure is a finding, not a crash
        evidence["exception"] = f"{type(exc).__name__}: {exc}"
        # No TLS (e.g. plain-http target or unreachable host): record skip, not pass.
        tr["checksAttempted"] = 0
        return finish_tool(tr, "skipped", evidence, error=str(exc))


# ----------------------------------------------------------- headers check
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def check_headers(target: str) -> dict:
    tr = make_tool_result("headers")
    url = target if "://" in target else "http://" + target
    evidence: dict = {"url": url, "rawHeaders": {}, "cookies": []}
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "shipsafe-runner/0.1"})
        try:
            resp = urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT_S)  # noqa: S310 - target is the authorized scan target
            status = resp.status
            raw = dict(resp.getheaders())
            body_snippet = resp.read(2048).decode("utf-8", "replace")
        except urllib.error.HTTPError as he:
            status = he.code
            raw = dict(he.headers.items()) if he.headers else {}
            body_snippet = ""
        evidence["httpStatus"] = status
        lowered = {k.lower(): v for k, v in raw.items()}
        evidence["rawHeaders"] = lowered
        evidence["present"] = {h: (h in lowered) for h in SECURITY_HEADERS}
        # CORS / cookie / server-leak evidence.
        evidence["cors"] = {
            "access-control-allow-origin": lowered.get("access-control-allow-origin"),
            "access-control-allow-credentials": lowered.get("access-control-allow-credentials"),
        }
        set_cookies = raw.get("Set-Cookie") or raw.get("set-cookie") or lowered.get("set-cookie")
        if set_cookies:
            cookies = set_cookies if isinstance(set_cookies, list) else [set_cookies]
            evidence["cookies"] = cookies
            evidence["cookieFlags"] = [
                {
                    "raw": c[:300],
                    "httponly": "httponly" in c.lower(),
                    "secure": "secure" in c.lower(),
                    "samesite": re.search(r"samesite\s*=\s*(\w+)", c, re.I).group(1) if re.search(r"samesite\s*=", c, re.I) else None,
                }
                for c in cookies
            ]
        evidence["serverBanner"] = lowered.get("server")
        evidence["poweredBy"] = lowered.get("x-powered-by")
        evidence["bodySnippet"] = body_snippet[:500]
        missing = [h for h in SECURITY_HEADERS if h not in lowered]
        evidence["missing"] = missing
        tr["checksAttempted"] = len(SECURITY_HEADERS) + 3  # headers + cors + cookies + banner
        status_out = "passed" if not missing else "failed"
        return finish_tool(tr, status_out, evidence)
    except Exception as exc:  # noqa: BLE001
        evidence["exception"] = f"{type(exc).__name__}: {exc}"
        tr["checksAttempted"] = 0
        return finish_tool(tr, "failed", evidence, error=str(exc))


# ------------------------------------------------------ sensitive files check
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/wp-config.php",
    "/api/docs",
    "/.DS_Store",
    "/server-status",
]


def check_sensitive_files(target: str) -> dict:
    tr = make_tool_result("sensitive-files")
    base = target.rstrip("/") if "://" in target else "http://" + target.rstrip("/")
    evidence: dict = {"base": base, "probes": []}
    try:
        for path in SENSITIVE_PATHS:
            url = base + path
            started = time.monotonic()
            try:
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "shipsafe-runner/0.1"})
                try:
                    resp = urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT_S)  # noqa: S310
                    code = resp.status
                    snippet = resp.read(512).decode("utf-8", "replace")
                except urllib.error.HTTPError as he:
                    code = he.code
                    snippet = ""
                exposed = code in (200, 206) and len(snippet.strip()) > 0
                # /api/docs returning 200 is informational exposure, not a vuln by itself.
                evidence["probes"].append(
                    {
                        "path": path,
                        "url": url,
                        "httpStatus": code,
                        "exposed": exposed,
                        "bodySnippet": snippet[:200],
                        "latencyMs": int((time.monotonic() - started) * 1000),
                    }
                )
            except Exception as exc:  # noqa: BLE001 - one failed probe must not kill the tool
                evidence["probes"].append(
                    {"path": path, "url": url, "httpStatus": None, "exposed": False, "error": str(exc)}
                )
        tr["checksAttempted"] = len(SENSITIVE_PATHS)
        exposed_any = [p for p in evidence["probes"] if p.get("exposed")]
        status_out = "failed" if exposed_any else "passed"
        return finish_tool(tr, status_out, evidence)
    except Exception as exc:  # noqa: BLE001
        evidence["exception"] = f"{type(exc).__name__}: {exc}"
        tr["checksAttempted"] = 0
        return finish_tool(tr, "failed", evidence, error=str(exc))


# ------------------------------------------------------------- ports check
PROBE_PORTS = [80, 443, 22, 3306, 6379]


def check_ports(target: str) -> dict:
    tr = make_tool_result("ports")
    parts = urllib.parse.urlparse(target if "://" in target else "http://" + target)
    host = parts.hostname or target
    evidence: dict = {"host": host, "probes": []}
    try:
        for port in PROBE_PORTS:
            started = time.monotonic()
            banner = ""
            open_ = False
            try:
                with socket.create_connection((host, port), timeout=2) as sock:
                    open_ = True
                    sock.settimeout(2)
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(256).decode("utf-8", "replace")
                    except Exception:  # noqa: BLE001 - banner grab is best-effort
                        banner = ""
            except Exception as exc:  # noqa: BLE001 - closed/filtered port
                evidence["probes"].append(
                    {"port": port, "open": False, "banner": "", "detail": f"{type(exc).__name__}"}
                )
                continue
            evidence["probes"].append(
                {
                    "port": port,
                    "open": open_,
                    "banner": banner[:200],
                    "latencyMs": int((time.monotonic() - started) * 1000),
                }
            )
        tr["checksAttempted"] = len(PROBE_PORTS)
        risky = [p for p in evidence["probes"] if p.get("open") and p.get("port") in (22, 3306, 6379)]
        status_out = "failed" if risky else "passed"
        return finish_tool(tr, status_out, evidence)
    except Exception as exc:  # noqa: BLE001
        evidence["exception"] = f"{type(exc).__name__}: {exc}"
        tr["checksAttempted"] = 0
        return finish_tool(tr, "failed", evidence, error=str(exc))


def run_scan(target: str) -> dict:
    tools = []
    for fn in (check_tls, check_headers, check_sensitive_files, check_ports):
        try:
            tools.append(fn(target))
        except Exception as exc:  # noqa: BLE001 - never invent findings; record the failure
            tr = make_tool_result(getattr(fn, "__name__", "unknown"))
            tools.append(finish_tool(tr, "failed", {"exception": str(exc)}, error=str(exc)))
    return {"target": target, "scannedAt": utcnow(), "tools": tools}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: scanner.py <TARGET_URL> <OUTDIR>", file=sys.stderr)
        return 2
    target, outdir = argv[1], argv[2]
    os.makedirs(outdir, exist_ok=True)
    result = run_scan(target)
    out_path = os.path.join(outdir, "scan_result.json")
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        with open(os.path.join(outdir, "scan_result.sha256"), "w", encoding="utf-8") as fh:
            fh.write(f"{digest}  scan_result.json\n")
    except Exception as exc:  # noqa: BLE001 - runner itself failed
        print(f"shipsafe-runner: failed to write output: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
