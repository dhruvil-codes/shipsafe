/**
 * @shipsafe/scoring — deterministic finding explainer.
 *
 * `explain()` returns a structured remediation brief (what happened, why it
 * matters, copy-paste fix, how to verify) from fixed templates keyed by
 * `ruleId`. It NEVER invents vulnerabilities: unknown rule IDs fall back to
 * the finding's own deterministic title/description/remediation text.
 * The LLM analyst layer (another workstream) may rephrase this brief, but
 * this brief is always available without any model call.
 */
import type { NormalizedFinding } from '@shipsafe/shared';

export interface Explanation {
  /** What happened (observed fact from scanner evidence). */
  what: string;
  /** Why it matters (impact the evidence supports). */
  why: string;
  /** Copy-pasteable code/config snippet that fixes it. */
  fix: string;
  /** How to verify the fix. */
  verify: string;
}

const TEMPLATES: Record<string, Explanation> = {
  'TLS-CERT-EXPIRED': {
    what: 'The server presented a TLS certificate whose validity period has ended.',
    why: 'Validating clients refuse to connect (outage for strict clients), while non-validating clients lose all protection against interception.',
    fix: 'Renew via ACME and reload the server:\n\n```bash\ncertbot renew --deploy-hook "nginx -s reload"\n```',
    verify: 'Run `echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | openssl x509 -noout -dates` and confirm notAfter is in the future, then re-run the ShipSafe scan.',
  },
  'TLS-CERT-SELF-SIGNED': {
    what: 'The server presented a self-signed certificate not anchored in any public trust store.',
    why: 'Browsers show full-page warnings and API clients with default settings reject the connection; users trained to click through become phishable.',
    fix: 'Install a publicly trusted certificate. With Caddy this is automatic:\n\n```\napp.example.com {\n  reverse_proxy localhost:3000\n}\n```',
    verify: 'Load the site in a fresh browser profile with no exceptions added and confirm no certificate warning, then re-run the ShipSafe scan.',
  },
  'TLS-PROTOCOL-DEPRECATED': {
    what: 'The server still negotiates a deprecated protocol (SSLv2/SSLv3 or TLS 1.0/1.1).',
    why: 'These protocols have known cryptographic breaks (POODLE, BEAST-class) and auditors flag them as automatic failures.',
    fix: 'Set the protocol floor to TLS 1.2+ (nginx):\n\n```nginx\nssl_protocols TLSv1.2 TLSv1.3;\n```',
    verify: 'Run `nmap --script ssl-enum-ciphers -p 443 HOST` and confirm only TLS 1.2/1.3 are offered, then re-run the ShipSafe scan.',
  },
  'TLS-CIPHER-WEAK': {
    what: 'The server accepts weak cipher suites (e.g. RC4, 3DES, MD5, NULL or EXPORT-grade).',
    why: 'A network attacker can force negotiation of a breakable suite and decrypt or tamper with traffic.',
    fix: 'Restrict to AEAD suites (nginx):\n\n```nginx\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers on;\n```',
    verify: 'Re-run the TLS scanner and confirm no weak suite is listed, then re-run the ShipSafe scan.',
  },
  'HEADER-HSTS-MISSING': {
    what: 'HTTPS responses do not include a Strict-Transport-Security header.',
    why: 'Without HSTS, browsers can be downgraded to plain HTTP on hostile networks (SSL-stripping), exposing sessions and credentials.',
    fix: 'Send HSTS on all HTTPS responses (nginx):\n\n```nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n```',
    verify: 'Run `curl -sI https://HOST | grep -i strict-transport` and confirm the header is present, then re-run the ShipSafe scan.',
  },
  'HEADER-HSTS-WEAK': {
    what: 'The HSTS policy is present but its max-age is short or missing.',
    why: 'A short max-age lets the protection lapse for returning visitors, reopening the SSL-stripping window.',
    fix: 'Raise max-age to at least one year:\n\n```nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n```',
    verify: 'Confirm `curl -sI https://HOST` shows max-age >= 31536000, then re-run the ShipSafe scan.',
  },
  'HEADER-CSP-MISSING': {
    what: 'Responses do not include a Content-Security-Policy.',
    why: 'Without CSP there is no browser-enforced last line of defense: any injected script runs with full page privileges (XSS impact).',
    fix: 'Send a restrictive policy and tighten iteratively:\n\n```\nContent-Security-Policy: default-src \'self\'; object-src \'none\'; base-uri \'self\'\n```',
    verify: 'Confirm the header with `curl -sI https://HOST`, check the browser console for violations on key pages, then re-run the ShipSafe scan.',
  },
  'HEADER-FRAME-MISSING': {
    what: 'Neither X-Frame-Options nor a CSP frame-ancestors directive is set.',
    why: 'The page can be embedded in an attacker iframe, enabling clickjacking (tricking users into unintended clicks/actions).',
    fix: 'Deny framing (nginx):\n\n```nginx\nadd_header X-Frame-Options "DENY" always;\n```\n(Or add `frame-ancestors \'none\'` to your CSP.)',
    verify: 'Confirm the header with `curl -sI https://HOST`, then re-run the ShipSafe scan.',
  },
  'HEADER-XCTO-MISSING': {
    what: 'Responses do not send `X-Content-Type-Options: nosniff`.',
    why: 'Browsers may MIME-sniff responses and execute attacker-influenced content (e.g. an uploaded file) as script.',
    fix: 'Send the header on all responses (nginx):\n\n```nginx\nadd_header X-Content-Type-Options "nosniff" always;\n```',
    verify: 'Confirm the header with `curl -sI https://HOST`, then re-run the ShipSafe scan.',
  },
  'HEADER-REFERRER-MISSING': {
    what: 'No Referrer-Policy is set, so browsers use the default referrer behavior.',
    why: 'Full internal URLs — occasionally including tokens in query strings — can leak to third-party sites via the Referer header.',
    fix: 'Send a conservative policy:\n\n```\nReferrer-Policy: strict-origin-when-cross-origin\n```',
    verify: 'Confirm the header with `curl -sI https://HOST`, then re-run the ShipSafe scan.',
  },
  'HEADER-VERSION-DISCLOSURE': {
    what: 'A response header advertises the exact server/framework version.',
    why: 'Version banners let attackers aim version-specific exploits instead of probing blindly.',
    fix: 'Generalize banners (nginx + framework):\n\n```nginx\nserver_tokens off;\n```\n```js\n// Express: disable the fingerprint header\napp.disable("x-powered-by");\n```',
    verify: 'Confirm `curl -sI https://HOST` no longer shows a version, then re-run the ShipSafe scan.',
  },
  'CORS-WILDCARD-CREDENTIALS': {
    what: 'CORS allows any origin (`*`) while credentialed requests are permitted.',
    why: 'Any website can issue authenticated cross-origin requests in a victim browser and read the responses — equivalent to missing authorization on reads.',
    fix: 'Allowlist explicit origins (Express):\n\n```js\nconst ALLOW = new Set(["https://app.example.com"]);\napp.use(cors({\n  origin: (o, cb) => cb(null, ALLOW.has(o)),\n  credentials: true,\n}));\n```',
    verify: 'Send a request with `Origin: https://evil.example` and confirm it is NOT reflected, then re-run the ShipSafe scan.',
  },
  'CORS-WILDCARD': {
    what: 'CORS allows any origin (`*`) on this endpoint.',
    why: 'Any website can read responses. Acceptable for public data, dangerous for anything user-specific or non-public.',
    fix: 'Restrict to the origins that need access:\n\n```\nAccess-Control-Allow-Origin: https://app.example.com\nVary: Origin\n```',
    verify: 'Confirm unlisted origins receive no ACAO header, then re-run the ShipSafe scan.',
  },
  'CORS-ORIGIN-REFLECTED': {
    what: 'The server echoes the request Origin in Access-Control-Allow-Origin.',
    why: 'Any website can read authenticated cross-origin responses in a victim browser — the allowlist provides no protection.',
    fix: 'Validate against an explicit allowlist instead of reflecting:\n\n```js\nconst ALLOW = new Set(["https://app.example.com"]);\nif (ALLOW.has(req.headers.origin)) res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n```',
    verify: 'Request with `Origin: https://evil.example` and confirm no ACAO header is returned, then re-run the ShipSafe scan.',
  },
  'COOKIE-NO-SECURE': {
    what: 'A cookie is set without the Secure attribute.',
    why: 'Browsers will transmit the cookie over plain HTTP, where it can be intercepted (session hijacking) on hostile networks.',
    fix: 'Set the flag when issuing the cookie (Express):\n\n```js\nres.cookie("session", value, { secure: true, httpOnly: true, sameSite: "lax" });\n```',
    verify: 'Inspect Set-Cookie in devtools/network log and confirm `Secure` is present, then re-run the ShipSafe scan.',
  },
  'COOKIE-NO-HTTPONLY': {
    what: 'A cookie is set without the HttpOnly attribute.',
    why: 'Any XSS flaw can read the cookie via JavaScript and exfiltrate sessions or tokens.',
    fix: 'Add HttpOnly unless script access is strictly required:\n\n```js\nres.cookie("session", value, { httpOnly: true, secure: true, sameSite: "lax" });\n```',
    verify: 'Confirm `HttpOnly` in the Set-Cookie response header, then re-run the ShipSafe scan.',
  },
  'COOKIE-NO-SAMESITE': {
    what: 'A cookie is set without a SameSite attribute.',
    why: 'The cookie is sent with cross-site requests, exposing state-changing endpoints to CSRF.',
    fix: 'Default to Lax or Strict:\n\n```js\nres.cookie("session", value, { sameSite: "lax", secure: true, httpOnly: true });\n```',
    verify: 'Confirm `SameSite=Lax` (or Strict) in Set-Cookie, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-ENV-EXPOSED': {
    what: 'An environment file (.env) is readable over HTTP.',
    why: '.env files routinely hold database credentials, API keys, and session secrets — this is a full credential compromise until rotated.',
    fix: 'Deny access at the web server (nginx):\n\n```nginx\nlocation ~ /\\.env { deny all; }\n```\nThen move secrets out of the document root and ROTATE every exposed credential.',
    verify: 'Confirm `curl -I https://HOST/.env` returns 403/404, rotate all exposed secrets, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-KEY-EXPOSED': {
    what: 'Private key material is readable over HTTP.',
    why: 'Whoever downloads the key can impersonate the service it belongs to (TLS, SSH, signing) and decrypt captured traffic.',
    fix: 'Remove the file from the document root immediately:\n\n```bash\nrm /var/www/html/*.pem /var/www/html/*.key\n```\nThen revoke and re-issue the key/certificate and audit for misuse.',
    verify: 'Confirm the URL returns 403/404, complete key rotation, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-GIT-EXPOSED': {
    what: 'The .git directory is readable over HTTP.',
    why: 'Attackers can reconstruct the full repository — source, history, and secrets committed in the past.',
    fix: 'Block it at the web server (nginx):\n\n```nginx\nlocation ~ /\\.git { deny all; }\n```\nThen rotate any secret ever committed and redeploy from a clean checkout.',
    verify: 'Confirm `curl -I https://HOST/.git/HEAD` returns 403/404, rotate exposed secrets, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-BACKUP-EXPOSED': {
    what: 'A backup, dump, or config copy is readable over HTTP.',
    why: 'Such copies frequently embed production credentials and database contents.',
    fix: 'Delete copies from the document root and block the extensions:\n\n```nginx\nlocation ~* \\.(sql|bak|backup|dump|old|orig)$ { deny all; }\n```',
    verify: 'Confirm the URL returns 403/404 and rotate any credentials found inside, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-DEBUG-EXPOSED': {
    what: 'A debug/diagnostic endpoint is reachable in production.',
    why: 'It discloses internal configuration, paths, and versions that accelerate further attacks.',
    fix: 'Disable debug endpoints in production:\n\n```python\n# Django example\nDEBUG = False\nALLOWED_HOSTS = ["app.example.com"]\n```',
    verify: 'Confirm the endpoint no longer responds with diagnostics, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-STATUS-EXPOSED': {
    what: 'A server-status page is reachable by unauthenticated visitors.',
    why: 'It discloses worker state, request URLs, and client addresses — live reconnaissance.',
    fix: 'Restrict to localhost (Apache):\n\n```apache\n<Location /server-status>\n  Require ip 127.0.0.1\n</Location>\n```',
    verify: 'Confirm remote requests get 403, then re-run the ShipSafe scan.',
  },
  'API-DOCS-EXPOSED': {
    what: 'Machine-readable API documentation is publicly reachable.',
    why: 'Attackers gain a complete endpoint/schema inventory to probe for authorization flaws (BOLA).',
    fix: 'Gate docs behind authentication (Express):\n\n```js\napp.use("/api-docs", requireAuth, swaggerUi.serve, swaggerUi.setup(spec));\n```',
    verify: 'Confirm unauthenticated requests get 401/403, then re-run the ShipSafe scan.',
  },
  'SENSITIVE-DSSTORE-EXPOSED': {
    what: 'A .DS_Store file is readable over HTTP.',
    why: 'It reveals internal directory and file names, aiding targeted probing.',
    fix: 'Remove and exclude from deploys:\n\n```bash\nfind . -name .DS_Store -delete\necho .DS_Store >> .gitignore\n```',
    verify: 'Confirm the URL returns 403/404, then re-run the ShipSafe scan.',
  },
  'PORT-DB-EXPOSED': {
    what: 'A database service port accepts connections from the network.',
    why: 'Directly reachable databases face brute-force and exploit attempts; one weak credential away from full data compromise.',
    fix: 'Firewall to application hosts only (nftables):\n\n```bash\nnft add rule inet filter input tcp dport 5432 ip saddr @app_hosts accept\nnft add rule inet filter input tcp dport 5432 drop\n```',
    verify: 'Confirm the port is closed/filtered from untrusted networks (`nmap -p PORT HOST`), then re-run the ShipSafe scan.',
  },
  'PORT-TELNET-EXPOSED': {
    what: 'Telnet (port 23) is reachable.',
    why: 'Telnet transmits credentials and sessions in cleartext — trivially intercepted.',
    fix: 'Disable telnet and use SSH with key authentication:\n\n```bash\nsystemctl disable --now telnet.socket\n```',
    verify: 'Confirm port 23 is closed (`nmap -p 23 HOST`), then re-run the ShipSafe scan.',
  },
  'PORT-FTP-EXPOSED': {
    what: 'FTP (port 21) is reachable.',
    why: 'Classic FTP sends credentials in cleartext and is a common anonymous-access vector.',
    fix: 'Replace with SFTP; if FTP must stay, restrict to trusted networks:\n\n```bash\nnft add rule inet filter input tcp dport 21 ip saddr @trusted accept\n```',
    verify: 'Confirm anonymous login is disabled and the port is restricted, then re-run the ShipSafe scan.',
  },
  'PORT-REMOTE-ADMIN-EXPOSED': {
    what: 'A remote-administration port (SSH/RDP/VNC) is reachable from the network.',
    why: 'Exposed admin services attract continuous brute-force and exploit scanning.',
    fix: 'Restrict to bastion/VPN sources and harden auth (SSH):\n\n```\nPasswordAuthentication no\nPermitRootLogin no\n```',
    verify: 'Confirm only bastion IPs can connect and key/MFA auth is enforced, then re-run the ShipSafe scan.',
  },
  'ERROR-DISCLOSURE': {
    what: 'The application returned a verbose error (stack trace or debug page).',
    why: 'Stack traces disclose code paths, library versions, and configuration that focus further attacks.',
    fix: 'Return generic errors to clients; log details server-side (Express):\n\n```js\napp.use((err, req, res, next) => {\n  logger.error({ err });\n  res.status(500).send("Something went wrong");\n});\n```',
    verify: 'Trigger the error and confirm only a generic message is returned, then re-run the ShipSafe scan.',
  },
};

/**
 * Structured remediation brief for a finding. Deterministic: the same
 * finding always yields the same brief. Unknown rule IDs fall back to the
 * finding's own deterministic text (never invented content).
 */
export function explain(finding: NormalizedFinding): Explanation {
  const template = TEMPLATES[finding.ruleId];
  if (template) return { ...template };
  return {
    what: `${finding.title}. ${finding.description}`,
    why: `This issue was confirmed by scanner evidence (severity ${finding.severity}${finding.cwe ? `, ${finding.cwe}` : ''}${finding.owasp ? `, OWASP ${finding.owasp}` : ''}). Review the evidence reference before prioritizing.`,
    fix: finding.remediation,
    verify: 'Re-run the ShipSafe scan after applying the remediation and confirm this finding no longer appears.',
  };
}
