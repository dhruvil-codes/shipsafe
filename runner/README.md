# ShipSafe In-VM Runner

Runs **inside** the disposable InstaBox Debian 13 scan VM, against the authorized
target only. Pull model (S-09): the orchestrator drives the VM via the
`SandboxProvider`; the runner never calls back to the control plane and holds
no ShipSafe credentials.

## Files

| File | Purpose |
| ---- | ------- |
| `shipsafe-runner.sh` | Bash entrypoint: `shipsafe-runner.sh <TARGET_URL> <OUTDIR>` |
| `scanner.py` | Stdlib-only Python scanner (TLS, headers, sensitive files, ports) |
| `osint_engine.sh` | Bash entrypoint: installs the OSINT toolchain, then runs `osint_engine.py` |
| `osint_engine.py` | Stdlib-only OSINT orchestrator (subfinder, httpx, subzy, checkdmarc, whois) |
| `tests/` | Offline shape tests for `scan_result.json` + `osint_result.json` |

## Usage

```bash
./shipsafe-runner.sh https://app.example.com /work/out
# writes /work/out/scan_result.json + /work/out/scan_result.sha256
```

Or directly:

```bash
python3 scanner.py https://app.example.com /work/out
```

## Output contract

`scan_result.json`:

```json
{
  "target": "https://app.example.com",
  "scannedAt": "2026-10-15T12:00:00.000Z",
  "tools": [
    {
      "tool": "tls-probe",
      "toolVersion": "0.1.0",
      "status": "passed | failed | skipped",
      "startedAt": "...",
      "endedAt": "...",
      "durationMs": 123,
      "checksAttempted": 3,
      "evidence": {},
      "error": "optional"
    }
  ]
}
```

Invariants:

- **Evidence first** — every check carries raw evidence (`rawHeaders`,
  `peerCert`, probe statuses, banners). No finding without evidence.
- **No credit for what did not run** — unreachable/skipped tools are recorded
  as `skipped`/`failed`, never `passed`.
- **Partial failure is data** — the script exits `0` even when individual
  tools fail. Nonzero exit means the runner itself could not write output.
- **Mandatory teardown (S-19)** is the orchestrator's job: it must
  `kill` the sandbox after collecting `/work/out/*` and verifying the
  SHA-256 checksum.
- Reconciler labels on the sandbox: `scan_id`, `workspace_id`, `expires_at`.

## OSINT engine

`osint_engine.sh <TARGET_URL_OR_DOMAIN> <OUTDIR>` installs the official
open-source toolchain when missing (Go binaries for subfinder/httpx/subzy,
`pip install checkdmarc dnspython`, `apt-get install whois dnsutils`) and runs
`osint_engine.py`, which executes the **real binaries** sequentially —
`subfinder -d <domain> -silent`, `httpx -l <subs> -silent -json -tech-detect
-status-code -title`, `subzy run --targets <subs> --hide_fails`,
`checkdmarc -f json <domain>`, `whois <domain>` — and consolidates the raw
JSON stdout into a single `osint-suite` ToolResult
(`<OUTDIR>/osint_result.json` + `.sha256`).

Zero simulation: a missing/failed binary is recorded as `ran: false` with an
error and yields no findings. The adapter side (`normalizeOsint` in
`packages/adapters/src/osint.ts`) maps the evidence to `OSINT-DMARC-MISSING`
(HIGH), `OSINT-DMARC-PERMISSIVE` (MEDIUM), `OSINT-SUBDOMAIN-TAKEOVER`
(CRITICAL), `OSINT-EXPOSED-STAGING` (MEDIUM), and `OSINT-DOMAIN-EXPIRING`
(MEDIUM).

## Tests

```bash
# offline, stdlib only — no network required
python3 -m unittest discover -s runner/tests -v
```
