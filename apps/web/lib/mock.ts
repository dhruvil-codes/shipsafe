/** Offline-demo fixtures for the ShipSafe web UI.
 * Rendered when the scan API is unreachable, and for the /scan/demo sample report.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface MockFinding {
  id: string;
  severity: Severity;
  title: string;
  summary: string;
  affected: string;
  evidence: string;
  fix: string;
}

export const MOCK_SANDBOX_ID = "sbx_live_7f3a9c2e1b";

export const MOCK_LOGS: string[] = [
  "$ shipsafe-runner --profile baseline --target https://example.com",
  "[init] snapshot shipsafe-baseline-2026-10-09 (tools pinned, Trivy DB bundled)",
  "[net] egress allowlist applied: 93.184.216.34/32, dns 9.9.9.9; deny RFC1918, metadata",
  "[tls] probing https://example.com:443 ...",
  "[tls] OK: TLS 1.2+ only, certificate valid (issuer: DigiCert, expires in 214d)",
  "[headers] GET / -> 200 in 212ms",
  "[headers] WARN: content-security-policy header missing",
  "[headers] WARN: strict-transport-security max-age too short (600)",
  "[files] probing /.git/HEAD, /.env, /server-status ...",
  "[stderr] ffuf: /.git/HEAD -> 404 (0.4s); /.env -> 404 (0.3s)",
  "[files] OK: no sensitive files exposed (3/3 probes 404)",
  "[ports] scanning top 100 ports on 93.184.216.34 ...",
  "[ports] open: 80/tcp (http), 443/tcp (https); filtered: remainder",
  "[ports] WARN: port 8080/tcp open (http-proxy banner leaked)",
  "[zap] passive scan complete: 2 alerts (1 medium, 1 low)",
  "[done] 4/4 control groups assessed in 41.2s — normalizing findings",
];

export const MOCK_FINDINGS: MockFinding[] = [
  {
    id: "F-1042",
    severity: "critical",
    title: "Admin API reachable without authentication",
    summary:
      "The endpoint /api/admin/users returned HTTP 200 with customer records for an unauthenticated request. Authorization is not enforced on this route.",
    affected: "GET /api/admin/users",
    evidence:
      "GET /api/admin/users -> 200 OK (312ms)\n" +
      'Response body: {"users":[{"id":1,"email":"..."}, ...]} (redacted)\n' +
      "Request carried no session cookie or Authorization header.",
    fix: "Add an authorization check to the /api/admin/* route group so it requires the admin role; return 401/403 otherwise. Add a regression test that requests the route with no credentials and asserts a non-200 status.",
  },
  {
    id: "F-1043",
    severity: "high",
    title: "Content-Security-Policy header missing",
    summary:
      "The application sends no Content-Security-Policy header, leaving pages without a mitigation layer against cross-site scripting.",
    affected: "GET / (response headers)",
    evidence:
      "GET / -> 200 OK\n" +
      "Response headers: content-type, x-frame-options=DENY, x-content-type-options=nosniff\n" +
      "Missing: content-security-policy, strict-transport-security (adequate max-age)",
    fix: "Set a restrictive Content-Security-Policy, e.g. default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Verify no inline scripts break, then deploy and re-scan.",
  },
  {
    id: "F-1044",
    severity: "medium",
    title: "Unexpected proxy port open (8080/tcp)",
    summary:
      "Port 8080 is open and serves an HTTP proxy banner. It is not part of the declared scope and widens the attack surface.",
    affected: "93.184.216.34:8080/tcp",
    evidence:
      "nmap top-100: 80/tcp open, 443/tcp open, 8080/tcp open (http-proxy)\n" +
      "Banner: HTTP/1.1 400 Bad Request / Server: squid/5.9 (truncated)",
    fix: "Close port 8080 at the firewall/security group or bind the proxy to loopback. If the proxy is required, restrict it to allowlisted source IPs.",
  },
  {
    id: "F-1045",
    severity: "medium",
    title: "HSTS max-age too short",
    summary:
      "Strict-Transport-Security is set with max-age=600, which offers little protection once the window lapses.",
    affected: "GET / (strict-transport-security)",
    evidence: "strict-transport-security: max-age=600",
    fix: "Raise to max-age=31536000 and, once verified, add includeSubDomains. Submit the domain to the HSTS preload list if appropriate.",
  },
  {
    id: "F-1046",
    severity: "low",
    title: "Verbose error message discloses stack path",
    summary:
      "A 404 for /api/nope returns a framework stack trace that reveals internal file paths. Low severity on its own, useful for an attacker combined with other issues.",
    affected: "GET /api/nope",
    evidence:
      "GET /api/nope -> 404\n" +
      'Body: {"error":"... at /srv/app/routes/api.ts:87 ..."} (truncated)',
    fix: "Disable debug error pages in production; return a generic error shape and log details server-side only.",
  },
  {
    id: "F-1047",
    severity: "info",
    title: "security.txt not published",
    summary:
      "No /.well-known/security.txt was found. Publishing one gives researchers a contact point for disclosures.",
    affected: "/.well-known/security.txt",
    evidence: "GET /.well-known/security.txt -> 404",
    fix: "Publish /.well-known/security.txt with Contact and Expires fields per RFC 9116.",
  },
];

/** Score shown with the mock report. Capped at 40 because F-1042 (critical) is open (PRD Section 15). */
export const MOCK_SCORE = 38;
export const MOCK_COVERAGE = 86;
