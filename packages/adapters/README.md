# @shipsafe/adapters

Deterministic normalization of raw scanner `ToolResult` evidence into
`NormalizedFinding[]`. Pure functions, no I/O, no LLM.

## API

- `normalize(toolResults, target)` — main entry point. Only `status:
  'passed'` results produce findings; `failed`/`skipped` yield zero findings.
  Output is deduplicated by fingerprint and sorted by ruleId/title.
- `fingerprintFor(target, category, ruleId, title)` — `sha256(...)` hex, 16 chars.
- `redactSecrets(value)` — deep-clone with tokens/cookies/secret keys replaced
  by `[REDACTED]`; applied to all finding evidence before persistence.
- `RULE_CATALOG` — every emittable rule (id, severity, category, CWE, OWASP).

## Evidence contract (for the runner workstream)

Parsers key off evidence *shape*, not tool names. Supported sections:

- TLS: `{ cert: { expired?, validTo?, issuer?, subject?, selfSigned? },
  protocols?: string[] | { version, enabled? }[] | Record<string, boolean>,
  weakCiphers?: string[], ciphers?: string[] | { name, weak? }[] }`
- Headers: `{ headers: Record<string,string>, cookies?: ({ name, secure?,
  httpOnly?, sameSite? } | "name=val; Secure")[], cors?: { allowOrigin?,
  allowCredentials?, reflectedOrigin? } }` (flat header map also accepted;
  prefer `evidence.cookies` array form for correct multi-cookie parsing)
- Sensitive paths: `{ probes | results | exposedPaths | paths:
  Array<string | { path, status?, exposed? }> }`. Only confirmed exposure
  (explicit `exposed: true` or 2xx on a known-sensitive pattern) creates a
  finding; 3xx/401/403/404 and unknown patterns never do.
- Ports: `{ openPorts | ports: Array<number | { port, state?, service? }> }`.
  Only sensitive ports flag (DB set, 21/23, 22/3389/5900); web ports
  (80/443/8000/8080/8443/3000) and unknown ports never do.
- Errors: `{ errorDisclosure: true, errorSample?: string }`.

Findings never store cookie values or secret material — parsers keep names and
flags only, and `redactSecrets` scrubs the rest.
