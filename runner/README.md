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
| `tests/` | Offline shape tests for `scan_result.json` |

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

## Tests

```bash
# offline, stdlib only — no network required
python3 -m unittest discover -s runner/tests -v
```
