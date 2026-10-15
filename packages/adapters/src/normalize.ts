/**
 * @shipsafe/adapters — deterministic normalization of raw scanner evidence
 * into {@link NormalizedFinding} records.
 *
 * Design notes (invariants Evidence First / No Credit for Unrun):
 * - Only `ToolResult`s with `status: 'passed'` can produce findings.
 *   `failed` and `skipped` results yield ZERO findings, always.
 * - Every finding needs confirmed evidence in the tool output. A missing,
 *   null, or unrecognized evidence section yields no finding — never a pass,
 *   never a fabricated weakness.
 * - Parsers key off the *shape* of `evidence`, not the tool name, so runner
 *   tool renames do not silently change findings. Each parser is a no-op when
 *   its evidence section is absent. Overlaps across tools are removed by
 *   fingerprint de-duplication.
 * - Finding `evidence` is passed through {@link redactSecrets} so tokens,
 *   cookies, and Authorization material can never reach persistence.
 * - One finding per affected resource (per path, per port, per cookie issue),
 *   so retest/comparison can resolve issues individually. Fingerprint =
 *   `sha256(target|category|ruleId|title)` truncated to 16 hex chars.
 *
 * Expected evidence shapes (see README.md for the full contract):
 * - TLS:        `{ cert: { expired?, validTo?, issuer?, subject?, selfSigned? },
 *                  protocols?: Array<string | { version, enabled? }> | Record<string, boolean>,
 *                  weakCiphers?: string[], ciphers?: Array<string | { name, weak? }> }`
 * - Headers:    `{ headers: Record<string,string>, cookies?: [...], cors?: {...} }`
 *               (a flat header map is also accepted)
 * - Sensitive:  `{ probes | results | exposedPaths | paths: Array<string | { path, status?, exposed? }> }`
 * - Ports:      `{ openPorts | ports: Array<number | { port, state?, service? }> }`
 * - Errors:     `{ errorDisclosure: true, errorSample?: string }`
 */
import { createHash } from 'node:crypto';
import {
  ToolResultSchema,
  type FindingCategory,
  type NormalizedFinding,
  type Severity,
  type ToolResult,
} from '@shipsafe/shared';

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/** Stable 16-hex-char fingerprint: sha256(target|category|ruleId|title). */
export function fingerprintFor(
  target: string,
  category: string,
  ruleId: string,
  title: string,
): string {
  return createHash('sha256')
    .update(`${target}|${category}|${ruleId}|${title}`)
    .digest('hex')
    .slice(0, 16);
}

// ---------------------------------------------------------------------------
// Secret redaction (applied to all finding evidence before persistence)
// ---------------------------------------------------------------------------

/** Object keys whose string values are secrets and must not be persisted. */
const SENSITIVE_KEY =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|.*token.*|.*secret.*|passwd|password|pwd|.*credential.*|private[_-]?key|session[_-]?id|session[_-]?token|auth[_-]?token)$/i;

/** `[name, value]` pairs (e.g. cookie jars) whose value must be redacted. */
const SENSITIVE_PAIR_NAME = /cookie|session|token|auth|secret|key|password/i;

/** String-level secret patterns -> replacement. */
const STRING_PATTERNS: Array<[RegExp, string]> = [
  // Authorization / Proxy-Authorization headers (any scheme incl. Bearer).
  [/(authorization\s*:\s*(?:bearer\s+)?)[^\s"';,]+/gi, '$1[REDACTED]'],
  [/(proxy-authorization\s*:\s*(?:bearer\s+)?)[^\s"';,]+/gi, '$1[REDACTED]'],
  // Bare Bearer tokens.
  [/(bearer\s+)[A-Za-z0-9\-._~+/=]+/gi, '$1[REDACTED]'],
  // key=value / key: value secret assignments in text.
  [
    /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret|private[_-]?key|password|passwd|pwd)\s*[:=]\s*["']?)([^"'\s;,}]+)/gi,
    '$1[REDACTED]',
  ],
  // Query-string / fragment secrets (?token=abc&...).
  [/([?&](?:token|key|secret|password|auth|sessionid)=)[^&\s"'<]+/gi, '$1[REDACTED]'],
  // URI-embedded credentials (postgres://user:pass@host, https://user:pass@host).
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@?#]+:)([^@\s/?#"']+)(@)/gi, '$1[REDACTED]$3'],
  // Set-Cookie response lines: keep the cookie name, redact the value.
  [/(set-cookie\s*:\s*[^\s=;]+=\s*)([^;\r\n]+)/gi, '$1[REDACTED]'],
];

function redactString(s: string): string {
  let out = s;
  for (const [re, replacement] of STRING_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, replacement);
  }
  return out;
}

/**
 * Deep-clone `value`, replacing secret material with `[REDACTED]`.
 * Handles nested objects/arrays, secret-named keys, Bearer/secret string
 * patterns, Set-Cookie lines, and Cookie-header value lists.
 */
export function redactSecrets<T>(value: T): T {
  if (typeof value === 'string') return redactString(value) as T;
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item)) as T;
  }
  if (value !== null && typeof value === 'object') {
    if (value instanceof Date || value instanceof RegExp) return value;
    const obj = value as Record<string, unknown>;
    // `{ name, value }` pairs such as cookie-jar entries: redact by name.
    if (
      typeof obj['name'] === 'string' &&
      typeof obj['value'] === 'string' &&
      SENSITIVE_PAIR_NAME.test(obj['name'] as string)
    ) {
      return { ...obj, value: '[REDACTED]' } as T;
    }
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(obj)) {
      if (SENSITIVE_KEY.test(key)) {
        if (typeof entry === 'string') {
          if (/cookie/i.test(key)) {
            out[key] = entry.replace(/=([^;,\s]+)/g, '=[REDACTED]');
          } else {
            const redacted = redactString(entry);
            out[key] = redacted === entry ? '[REDACTED]' : redacted;
          }
        } else if (entry !== null && typeof entry === 'object') {
          out[key] = redactSecrets(entry);
        } else {
          out[key] = entry;
        }
      } else {
        out[key] = redactSecrets(entry);
      }
    }
    return out as T;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Internal draft type + rule catalog
// ---------------------------------------------------------------------------

interface DraftFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string;
  owasp: string;
  remediation: string;
  evidence: unknown;
}

export interface RuleMeta {
  ruleId: string;
  label: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string;
  owasp: string;
}

/**
 * Every rule this normalizer can emit. The scoring explainer is tested
 * against this catalog so no rule ships without remediation text.
 */
export const RULE_CATALOG: RuleMeta[] = [
  { ruleId: 'TLS-CERT-EXPIRED', label: 'Expired TLS certificate', severity: 'HIGH', category: 'web', cwe: 'CWE-295', owasp: 'A02:2021' },
  { ruleId: 'TLS-CERT-SELF-SIGNED', label: 'Self-signed TLS certificate', severity: 'MEDIUM', category: 'web', cwe: 'CWE-295', owasp: 'A02:2021' },
  { ruleId: 'TLS-PROTOCOL-DEPRECATED', label: 'Deprecated TLS protocol enabled', severity: 'HIGH', category: 'web', cwe: 'CWE-326', owasp: 'A02:2021' },
  { ruleId: 'TLS-CIPHER-WEAK', label: 'Weak TLS cipher suite enabled', severity: 'MEDIUM', category: 'web', cwe: 'CWE-327', owasp: 'A02:2021' },
  { ruleId: 'HEADER-HSTS-MISSING', label: 'Missing HSTS header', severity: 'MEDIUM', category: 'web', cwe: 'CWE-319', owasp: 'A05:2021' },
  { ruleId: 'HEADER-HSTS-WEAK', label: 'Weak HSTS policy', severity: 'LOW', category: 'web', cwe: 'CWE-319', owasp: 'A05:2021' },
  { ruleId: 'HEADER-CSP-MISSING', label: 'Missing Content-Security-Policy', severity: 'MEDIUM', category: 'web', cwe: 'CWE-693', owasp: 'A05:2021' },
  { ruleId: 'HEADER-FRAME-MISSING', label: 'Missing clickjacking protection', severity: 'LOW', category: 'web', cwe: 'CWE-1021', owasp: 'A05:2021' },
  { ruleId: 'HEADER-XCTO-MISSING', label: 'Missing X-Content-Type-Options', severity: 'LOW', category: 'web', cwe: 'CWE-693', owasp: 'A05:2021' },
  { ruleId: 'HEADER-REFERRER-MISSING', label: 'Missing Referrer-Policy', severity: 'INFO', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'HEADER-VERSION-DISCLOSURE', label: 'Server version disclosure', severity: 'LOW', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'CORS-WILDCARD-CREDENTIALS', label: 'CORS wildcard with credentials', severity: 'HIGH', category: 'api', cwe: 'CWE-942', owasp: 'A01:2021' },
  { ruleId: 'CORS-WILDCARD', label: 'CORS wildcard origin', severity: 'MEDIUM', category: 'api', cwe: 'CWE-942', owasp: 'A01:2021' },
  { ruleId: 'CORS-ORIGIN-REFLECTED', label: 'CORS origin reflection', severity: 'HIGH', category: 'api', cwe: 'CWE-942', owasp: 'A01:2021' },
  { ruleId: 'COOKIE-NO-SECURE', label: 'Cookie without Secure flag', severity: 'MEDIUM', category: 'auth', cwe: 'CWE-614', owasp: 'A05:2021' },
  { ruleId: 'COOKIE-NO-HTTPONLY', label: 'Cookie without HttpOnly flag', severity: 'LOW', category: 'auth', cwe: 'CWE-1004', owasp: 'A05:2021' },
  { ruleId: 'COOKIE-NO-SAMESITE', label: 'Cookie without SameSite attribute', severity: 'LOW', category: 'auth', cwe: 'CWE-1275', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-ENV-EXPOSED', label: 'Exposed environment file', severity: 'CRITICAL', category: 'source', cwe: 'CWE-538', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-KEY-EXPOSED', label: 'Exposed private key material', severity: 'CRITICAL', category: 'source', cwe: 'CWE-538', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-GIT-EXPOSED', label: 'Exposed git metadata', severity: 'CRITICAL', category: 'source', cwe: 'CWE-538', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-BACKUP-EXPOSED', label: 'Exposed backup/config copy', severity: 'HIGH', category: 'source', cwe: 'CWE-538', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-DEBUG-EXPOSED', label: 'Exposed debug endpoint', severity: 'MEDIUM', category: 'logging', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-STATUS-EXPOSED', label: 'Exposed server-status page', severity: 'MEDIUM', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'API-DOCS-EXPOSED', label: 'Exposed API documentation', severity: 'LOW', category: 'api', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'SENSITIVE-DSSTORE-EXPOSED', label: 'Exposed .DS_Store file', severity: 'LOW', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'PORT-DB-EXPOSED', label: 'Database port reachable', severity: 'HIGH', category: 'storage', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'PORT-TELNET-EXPOSED', label: 'Telnet port reachable', severity: 'HIGH', category: 'web', cwe: 'CWE-319', owasp: 'A05:2021' },
  { ruleId: 'PORT-FTP-EXPOSED', label: 'FTP port reachable', severity: 'MEDIUM', category: 'web', cwe: 'CWE-319', owasp: 'A05:2021' },
  { ruleId: 'PORT-REMOTE-ADMIN-EXPOSED', label: 'Remote-admin port reachable', severity: 'MEDIUM', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'ERROR-DISCLOSURE', label: 'Verbose error disclosure', severity: 'MEDIUM', category: 'logging', cwe: 'CWE-209', owasp: 'A05:2021' },
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function lowerKeys(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) out[key.toLowerCase()] = value;
  return out;
}

// ---------------------------------------------------------------------------
// TLS parser
// ---------------------------------------------------------------------------

const DEPRECATED_PROTOCOLS = new Set(['ssl20', 'ssl30', 'tls10', 'tls11']);
const WEAK_CIPHER_PATTERN = /rc4|des\b|3des|md5|null|export|anon|idea|seed/i;

function normalizeProtocolName(raw: string): string {
  return raw.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function collectProtocols(evidence: Record<string, unknown>): Array<{ name: string; enabled: boolean }> {
  const found: Array<{ name: string; enabled: boolean }> = [];
  const push = (name: unknown, enabled: unknown = true) => {
    if (typeof name !== 'string' || name.length === 0) return;
    found.push({ name, enabled: enabled !== false });
  };
  // Merge a nested `tls:` object if the runner grouped TLS evidence there.
  const merged: Record<string, unknown> = { ...evidence };
  if (isRecord(evidence['tls'])) Object.assign(merged, evidence['tls']);

  const protocols = merged['protocols'];
  if (Array.isArray(protocols)) {
    for (const item of protocols) {
      if (typeof item === 'string') push(item);
      else if (isRecord(item)) {
        push(
          (item['version'] ?? item['name'] ?? item['protocol']) as unknown,
          (item['enabled'] ?? item['offered'] ?? true) as unknown,
        );
      }
    }
  } else if (isRecord(protocols)) {
    for (const [name, enabled] of Object.entries(protocols)) push(name, enabled);
  }
  return found;
}

function collectWeakCiphers(evidence: Record<string, unknown>): string[] {
  const merged: Record<string, unknown> = { ...evidence };
  if (isRecord(evidence['tls'])) Object.assign(merged, evidence['tls']);
  const weak = new Set<string>();
  for (const name of asStringArray(merged['weakCiphers'])) weak.add(name);
  const ciphers = merged['ciphers'];
  if (Array.isArray(ciphers)) {
    for (const item of ciphers) {
      if (typeof item === 'string') {
        if (WEAK_CIPHER_PATTERN.test(item)) weak.add(item);
      } else if (isRecord(item) && typeof item['name'] === 'string') {
        if (item['weak'] === true || WEAK_CIPHER_PATTERN.test(item['name'])) {
          weak.add(item['name']);
        }
      }
    }
  }
  return [...weak];
}

function parseTls(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  const drafts: DraftFinding[] = [];
  const merged: Record<string, unknown> = { ...evidence };
  if (isRecord(evidence['tls'])) Object.assign(merged, evidence['tls']);

  // --- certificate ---
  const cert = merged['cert'];
  if (isRecord(cert)) {
    const validTo = cert['validTo'] ?? cert['notAfter'] ?? cert['expiry'] ?? cert['expiresAt'];
    let expired = cert['expired'] === true;
    if (!expired && typeof validTo === 'string') {
      const date = new Date(validTo);
      if (!Number.isNaN(date.getTime()) && date.getTime() < Date.now()) expired = true;
    }
    if (!expired && typeof cert['daysUntilExpiry'] === 'number' && cert['daysUntilExpiry'] <= 0) {
      expired = true;
    }
    if (expired) {
      drafts.push({
        ruleId: 'TLS-CERT-EXPIRED',
        title: 'TLS certificate is expired',
        description:
          'The server presented an X.509 certificate whose validity period has ended. Clients that validate certificates will refuse to connect; clients that do not are exposed to interception.',
        severity: 'HIGH',
        category: 'web',
        cwe: 'CWE-295',
        owasp: 'A02:2021',
        remediation:
          'Renew the certificate from your CA or ACME provider, install the full chain on the server, and confirm renewal automation (e.g. certbot renew) is scheduled before the next expiry.',
        evidence: {
          subject: cert['subject'] ?? null,
          issuer: cert['issuer'] ?? null,
          validTo: validTo ?? null,
        },
      });
    }
    const issuer = cert['issuer'];
    const subject = cert['subject'];
    const selfSigned =
      cert['selfSigned'] === true ||
      (typeof issuer === 'string' &&
        typeof subject === 'string' &&
        issuer.length > 0 &&
        issuer === subject);
    if (selfSigned && !expired) {
      drafts.push({
        ruleId: 'TLS-CERT-SELF-SIGNED',
        title: 'TLS certificate is self-signed',
        description:
          'The server presented a self-signed certificate that no public trust store validates. Browsers show interstitial warnings and API clients with default settings reject the connection.',
        severity: 'MEDIUM',
        category: 'web',
        cwe: 'CWE-295',
        owasp: 'A02:2021',
        remediation:
          'Install a certificate from a publicly trusted CA (or your ACME automation) on every public endpoint. Reserve self-signed certificates for local development only.',
        evidence: { subject: subject ?? null, issuer: issuer ?? null },
      });
    }
  }

  // --- protocols ---
  const deprecated = collectProtocols(evidence).filter(
    (p) => p.enabled && DEPRECATED_PROTOCOLS.has(normalizeProtocolName(p.name)),
  );
  const seenProtocols = new Set<string>();
  for (const proto of deprecated) {
    const key = normalizeProtocolName(proto.name);
    if (seenProtocols.has(key)) continue;
    seenProtocols.add(key);
    drafts.push({
      ruleId: 'TLS-PROTOCOL-DEPRECATED',
      title: `Deprecated TLS protocol enabled: ${proto.name}`,
      description: `The server negotiates ${proto.name}, which has known cryptographic weaknesses (POODLE/BEAST-class attacks, no modern AEAD suites) and is deprecated by RFC 8996.`,
      severity: 'HIGH',
      category: 'web',
      cwe: 'CWE-326',
      owasp: 'A02:2021',
      remediation:
        'Disable SSLv2/SSLv3 and TLS 1.0/1.1 on the server or load balancer and set the minimum protocol version to TLS 1.2 (prefer TLS 1.2+ with strong ciphers, ideally TLS 1.3).',
      evidence: { protocol: proto.name },
    });
  }

  // --- ciphers ---
  const weak = collectWeakCiphers(evidence);
  if (weak.length > 0) {
    drafts.push({
      ruleId: 'TLS-CIPHER-WEAK',
      title: `Weak TLS cipher suites enabled (${weak.length})`,
      description: `The server accepts cipher suites with known weaknesses (${weak
        .slice(0, 5)
        .join(', ')}${weak.length > 5 ? ', ...' : ''}). A network attacker can downgrade connections to a breakable suite.`,
      severity: 'MEDIUM',
      category: 'web',
      cwe: 'CWE-327',
      owasp: 'A02:2021',
      remediation:
        'Restrict the server cipher list to AEAD suites (TLS 1.3 suites plus TLS 1.2 ECDHE+AESGCM/CHACHA20-POLY1305), disable RC4/3DES/MD5/NULL/EXPORT suites, and re-test with the TLS scanner.',
      evidence: { weakCiphers: weak.slice(0, 10) },
    });
  }
  return drafts;
}

// ---------------------------------------------------------------------------
// HTTP security headers / cookies / CORS parser
// ---------------------------------------------------------------------------

const KNOWN_HEADER_KEYS = new Set([
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'set-cookie',
  'cookie',
]);

function getHeaders(evidence: unknown): Record<string, string> {
  if (!isRecord(evidence)) return {};
  const raw = isRecord(evidence['headers']) ? evidence['headers'] : evidence;
  const lowered = lowerKeys(raw as Record<string, unknown>);
  const keys = Object.keys(lowered);
  if (!isRecord(evidence['headers']) && !keys.some((k) => KNOWN_HEADER_KEYS.has(k))) return {};
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(lowered)) {
    if (typeof value === 'string') out[key] = value;
    else if (typeof value === 'number') out[key] = String(value);
    else if (Array.isArray(value)) out[key] = value.filter((v) => typeof v === 'string').join('\n');
  }
  return out;
}

interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

function parseCookieString(raw: string): ParsedCookie | null {
  const parts = raw.split(';').map((p) => p.trim()).filter((p) => p.length > 0);
  if (parts.length === 0) return null;
  const first = (parts[0] as string).split('=');
  const name = (first[0] as string).trim();
  if (!name) return null;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower === 'secure') secure = true;
    else if (lower === 'httponly') httpOnly = true;
    else if (lower.startsWith('samesite=')) sameSite = part.slice('samesite='.length).trim() || null;
  }
  return { name, secure, httpOnly, sameSite };
}

function collectCookies(evidence: Record<string, unknown>, headers: Record<string, string>): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];
  const push = (cookie: ParsedCookie | null) => {
    if (cookie && !cookies.some((c) => c.name.toLowerCase() === cookie.name.toLowerCase())) {
      cookies.push(cookie);
    }
  };
  const fromEvidence = evidence['cookies'] ?? evidence['setCookies'] ?? evidence['set_cookies'];
  if (Array.isArray(fromEvidence)) {
    for (const item of fromEvidence) {
      if (typeof item === 'string') push(parseCookieString(item));
      else if (isRecord(item) && typeof item['name'] === 'string') {
        push({
          name: item['name'],
          secure: item['secure'] === true,
          httpOnly: item['httpOnly'] === true || item['http_only'] === true,
          sameSite:
            typeof item['sameSite'] === 'string'
              ? (item['sameSite'] as string)
              : typeof item['samesite'] === 'string'
                ? (item['samesite'] as string)
                : null,
        });
      }
    }
  }
  const setCookie = headers['set-cookie'];
  if (typeof setCookie === 'string' && setCookie.length > 0) {
    // Multiple Set-Cookie lines arrive newline-joined (see getHeaders).
    // NOTE: a single folded line containing Expires=..., <date with comma>
    // is treated as one cookie — splitting that correctly requires the
    // array form, which runners SHOULD emit via evidence.cookies.
    for (const line of setCookie.split('\n')) push(parseCookieString(line));
  }
  return cookies;
}

function parseHeaders(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  const headers = getHeaders(evidence);
  if (Object.keys(headers).length === 0 && !isRecord(evidence['cors']) && evidence['cookies'] === undefined) {
    return [];
  }
  const drafts: DraftFinding[] = [];

  // --- HSTS ---
  const hsts = headers['strict-transport-security'];
  if (!hsts) {
    drafts.push({
      ruleId: 'HEADER-HSTS-MISSING',
      title: 'Missing Strict-Transport-Security header',
      description:
        'Responses do not include a Strict-Transport-Security header, so browsers may be tricked into downgrading HTTPS links to HTTP (SSL-stripping) on hostile networks.',
      severity: 'MEDIUM',
      category: 'web',
      cwe: 'CWE-319',
      owasp: 'A05:2021',
      remediation:
        'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses (add `preload` once eligible and submitted).',
      evidence: { header: 'strict-transport-security', observed: null },
    });
  } else {
    const maxAge = /max-age\s*=\s*(\d+)/i.exec(hsts);
    if (!maxAge || Number(maxAge[1]) < 31536000) {
      drafts.push({
        ruleId: 'HEADER-HSTS-WEAK',
        title: 'Weak Strict-Transport-Security policy',
        description: `The HSTS policy is present but its max-age is short or missing (${hsts}), so protection lapses quickly for returning visitors.`,
        severity: 'LOW',
        category: 'web',
        cwe: 'CWE-319',
        owasp: 'A05:2021',
        remediation: 'Raise HSTS max-age to at least 31536000 (one year) and include `includeSubDomains`.',
        evidence: { header: 'strict-transport-security', observed: hsts },
      });
    }
  }

  // --- CSP ---
  const csp = headers['content-security-policy'];
  if (!csp) {
    drafts.push({
      ruleId: 'HEADER-CSP-MISSING',
      title: 'Missing Content-Security-Policy header',
      description:
        'Responses do not include a Content-Security-Policy, leaving cross-site scripting and resource-injection flaws with no browser-enforced last line of defense.',
      severity: 'MEDIUM',
      category: 'web',
      cwe: 'CWE-693',
      owasp: 'A05:2021',
      remediation:
        "Send a restrictive `Content-Security-Policy` (e.g. `default-src 'self'`) and tighten it until no inline scripts or unexpected origins remain.",
      evidence: { header: 'content-security-policy', observed: null },
    });
  }

  // --- Clickjacking: X-Frame-Options or CSP frame-ancestors ---
  const frameOptions = headers['x-frame-options'];
  const hasFrameAncestors = !!csp && /frame-ancestors/i.test(csp);
  if (!frameOptions && !hasFrameAncestors) {
    drafts.push({
      ruleId: 'HEADER-FRAME-MISSING',
      title: 'Missing clickjacking protection',
      description:
        'Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so the application can be embedded in an attacker-controlled iframe (clickjacking).',
      severity: 'LOW',
      category: 'web',
      cwe: 'CWE-1021',
      owasp: 'A05:2021',
      remediation:
        "Send `X-Frame-Options: DENY` (or `SAMEORIGIN` where framing is required) or add `frame-ancestors 'none'` to the Content-Security-Policy.",
      evidence: { header: 'x-frame-options', observed: null },
    });
  }

  // --- X-Content-Type-Options ---
  const xcto = headers['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    drafts.push({
      ruleId: 'HEADER-XCTO-MISSING',
      title: 'Missing X-Content-Type-Options header',
      description:
        'Responses do not send `X-Content-Type-Options: nosniff`, so browsers may MIME-sniff responses and execute attacker-influenced content as script.',
      severity: 'LOW',
      category: 'web',
      cwe: 'CWE-693',
      owasp: 'A05:2021',
      remediation: 'Send `X-Content-Type-Options: nosniff` on all responses.',
      evidence: { header: 'x-content-type-options', observed: xcto ?? null },
    });
  }

  // --- Referrer-Policy (informational: minor leakage channel) ---
  if (!headers['referrer-policy']) {
    drafts.push({
      ruleId: 'HEADER-REFERRER-MISSING',
      title: 'Missing Referrer-Policy header',
      description:
        'No Referrer-Policy is set, so browsers fall back to the default referrer behavior, which can leak full internal URLs (including tokens in query strings) to third parties.',
      severity: 'INFO',
      category: 'web',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation: 'Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) on all responses.',
      evidence: { header: 'referrer-policy', observed: null },
    });
  }

  // --- Server version disclosure ---
  const server = headers['server'];
  if (typeof server === 'string' && /\/\d|v\d+\.\d+|\d+\.\d+/.test(server)) {
    drafts.push({
      ruleId: 'HEADER-VERSION-DISCLOSURE',
      title: `Server version disclosed: ${server}`,
      description: `The Server header advertises a specific software version (${server}), which lets attackers target known vulnerabilities in that release.`,
      severity: 'LOW',
      category: 'web',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Suppress or generalize the Server header (e.g. nginx `server_tokens off;`, Apache `ServerTokens Prod`) and remove X-Powered-By style headers.',
      evidence: { header: 'server', observed: server },
    });
  }
  for (const poweredBy of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const value = headers[poweredBy];
    if (typeof value === 'string' && value.length > 0) {
      drafts.push({
        ruleId: 'HEADER-VERSION-DISCLOSURE',
        title: `Technology fingerprint disclosed via ${poweredBy}`,
        description: `The ${poweredBy} header advertises the backend stack (${value}), which helps attackers pick version-specific exploits.`,
        severity: 'LOW',
        category: 'web',
        cwe: 'CWE-200',
        owasp: 'A05:2021',
        remediation: `Remove the ${poweredBy} header at the framework or reverse-proxy layer.`,
        evidence: { header: poweredBy, observed: value },
      });
    }
  }

  // --- Cookies (one finding per cookie issue; values never stored) ---
  for (const cookie of collectCookies(evidence, headers)) {
    const flagEvidence = { cookie: cookie.name, secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite };
    if (!cookie.secure) {
      drafts.push({
        ruleId: 'COOKIE-NO-SECURE',
        title: `Cookie "${cookie.name}" missing Secure attribute`,
        description: `The "${cookie.name}" cookie is set without the Secure attribute, so browsers will send it over plain HTTP where it can be intercepted on hostile networks.`,
        severity: 'MEDIUM',
        category: 'auth',
        cwe: 'CWE-614',
        owasp: 'A05:2021',
        remediation: `Set the Secure attribute on the "${cookie.name}" cookie (and serve the application over HTTPS only).`,
        evidence: flagEvidence,
      });
    }
    if (!cookie.httpOnly) {
      drafts.push({
        ruleId: 'COOKIE-NO-HTTPONLY',
        title: `Cookie "${cookie.name}" missing HttpOnly attribute`,
        description: `The "${cookie.name}" cookie is readable from JavaScript, so any cross-site scripting flaw can steal it.`,
        severity: 'LOW',
        category: 'auth',
        cwe: 'CWE-1004',
        owasp: 'A05:2021',
        remediation: `Set the HttpOnly attribute on the "${cookie.name}" cookie unless client-side script access is strictly required.`,
        evidence: flagEvidence,
      });
    }
    if (!cookie.sameSite) {
      drafts.push({
        ruleId: 'COOKIE-NO-SAMESITE',
        title: `Cookie "${cookie.name}" missing SameSite attribute`,
        description: `The "${cookie.name}" cookie has no SameSite attribute, so browsers send it with cross-site requests, enabling cross-site request forgery.`,
        severity: 'LOW',
        category: 'auth',
        cwe: 'CWE-1275',
        owasp: 'A05:2021',
        remediation: `Set \`SameSite=Lax\` (or \`Strict\`) on the "${cookie.name}" cookie; use \`SameSite=None; Secure\` only where cross-site use is required.`,
        evidence: flagEvidence,
      });
    }
  }

  // --- CORS ---
  const cors = isRecord(evidence['cors']) ? (evidence['cors'] as Record<string, unknown>) : {};
  const allowOrigin =
    typeof cors['allowOrigin'] === 'string' ? (cors['allowOrigin'] as string) : headers['access-control-allow-origin'];
  const allowCredentials =
    cors['allowCredentials'] === true || headers['access-control-allow-credentials'] === 'true';
  const reflected = cors['reflectedOrigin'] === true || cors['reflected'] === true;
  if (reflected) {
    drafts.push({
      ruleId: 'CORS-ORIGIN-REFLECTED',
      title: 'CORS policy reflects arbitrary origins',
      description:
        'The server echoes the request Origin in Access-Control-Allow-Origin, so any website can read authenticated cross-origin responses in a victim browser.',
      severity: 'HIGH',
      category: 'api',
      cwe: 'CWE-942',
      owasp: 'A01:2021',
      remediation:
        'Replace origin reflection with an explicit allowlist of trusted origins, and never combine it with `Access-Control-Allow-Credentials: true` for untrusted callers.',
      evidence: { allowOrigin: allowOrigin ?? 'reflected', allowCredentials },
    });
  } else if (allowOrigin === '*' && allowCredentials) {
    drafts.push({
      ruleId: 'CORS-WILDCARD-CREDENTIALS',
      title: 'CORS allows any origin with credentials',
      description:
        'Access-Control-Allow-Origin is `*` while credentials are allowed, so any website can issue authenticated cross-origin requests and read the responses.',
      severity: 'HIGH',
      category: 'api',
      cwe: 'CWE-942',
      owasp: 'A01:2021',
      remediation:
        'Restrict Access-Control-Allow-Origin to an explicit allowlist when credentials are used; use `*` only for unauthenticated public resources.',
      evidence: { allowOrigin, allowCredentials },
    });
  } else if (allowOrigin === '*') {
    drafts.push({
      ruleId: 'CORS-WILDCARD',
      title: 'CORS allows any origin',
      description:
        'Access-Control-Allow-Origin is `*`, so any website can read responses from this endpoint. Safe for public data, risky for anything user-specific or non-public.',
      severity: 'MEDIUM',
      category: 'api',
      cwe: 'CWE-942',
      owasp: 'A01:2021',
      remediation:
        'Confirm the endpoint serves only public data, or restrict Access-Control-Allow-Origin to the web origins that need it.',
      evidence: { allowOrigin, allowCredentials },
    });
  }

  return drafts;
}

// ---------------------------------------------------------------------------
// Sensitive-path parser
// ---------------------------------------------------------------------------

interface Probe {
  path: string;
  exposed: boolean;
  status: number | null;
}

function collectProbes(evidence: Record<string, unknown>): Probe[] {
  const probes: Probe[] = [];
  const lists = [evidence['probes'], evidence['results'], evidence['paths'], evidence['checks']];
  const exposedLists = [evidence['exposedPaths'], evidence['exposed'], evidence['hits']];
  const push = (path: unknown, exposed: boolean, status: unknown) => {
    if (typeof path !== 'string' || path.length === 0) return;
    probes.push({
      path,
      exposed,
      status: typeof status === 'number' ? status : null,
    });
  };
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (typeof item === 'string') {
        // Bare strings in a generic list are NOT confirmed exposure.
        push(item, false, null);
      } else if (isRecord(item)) {
        const path = item['path'] ?? item['url'] ?? item['target'];
        const status = item['status'] ?? item['statusCode'] ?? item['code'];
        let exposed: boolean | null = null;
        if (typeof item['exposed'] === 'boolean') exposed = item['exposed'];
        else if (item['found'] === true || item['accessible'] === true) exposed = true;
        else if (typeof status === 'number') {
          // 2xx = readable content confirmed. 3xx/401/403/404 prove nothing
          // about the sensitive content, so they are not findings.
          exposed = status >= 200 && status < 300;
        } else exposed = false;
        push(path, exposed === true, status);
      }
    }
  }
  for (const list of exposedLists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (typeof item === 'string') push(item, true, null);
      else if (isRecord(item)) {
        push(item['path'] ?? item['url'] ?? item['target'], true, item['status'] ?? null);
      }
    }
  }
  return probes;
}

interface PathRule {
  ruleId: string;
  title: (path: string) => string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string;
  owasp: string;
  remediation: string;
}

function classifySensitivePath(path: string): PathRule | null {
  if (/(^|\/)\.env($|[./])/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-ENV-EXPOSED',
      title: (p) => `Environment file exposed at ${p}`,
      description:
        'An environment file (.env) is readable over HTTP. These files routinely contain database credentials, API keys, and session secrets.',
      severity: 'CRITICAL',
      category: 'source',
      cwe: 'CWE-538',
      owasp: 'A05:2021',
      remediation:
        'Block .env files at the web server (deny `\\.env` in nginx/Apache), move secrets out of the document root, and rotate every credential that was in the exposed file.',
    };
  }
  if (/id_rsa|\.pem($|[?#])|\.key($|[?#])|\.p12($|[?#])|\.pfx($|[?#])|server\.key/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-KEY-EXPOSED',
      title: (p) => `Private key material exposed at ${p}`,
      description:
        'Private key material is readable over HTTP. Anyone who downloads it can impersonate the service (TLS, SSH, signing) that key belongs to.',
      severity: 'CRITICAL',
      category: 'source',
      cwe: 'CWE-538',
      owasp: 'A05:2021',
      remediation:
        'Remove key files from the document root immediately, revoke and re-issue the exposed keys/certificates, and audit for unauthorized use.',
    };
  }
  if (/\.git(\/|$)/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-GIT-EXPOSED',
      title: (p) => `Git metadata exposed at ${p}`,
      description:
        'The .git directory is readable over HTTP, allowing full reconstruction of the repository — including source code, history, and secrets committed in the past.',
      severity: 'CRITICAL',
      category: 'source',
      cwe: 'CWE-538',
      owasp: 'A05:2021',
      remediation:
        'Block `/.git` at the web server, purge any secrets from git history (rotate them — history rewrites do not un-leak), and redeploy from a clean checkout.',
    };
  }
  if (/\.sql($|[?#])|\.bak($|[?#])|\.backup($|[?#])|\.dump($|[?#])|\.old($|[?#])|\.orig($|[?#])|~($|[?#])|wp-config/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-BACKUP-EXPOSED',
      title: (p) => `Backup or config copy exposed at ${p}`,
      description:
        'A backup, dump, or config copy is readable over HTTP. These copies frequently embed production credentials and database contents.',
      severity: 'HIGH',
      category: 'source',
      cwe: 'CWE-538',
      owasp: 'A05:2021',
      remediation:
        'Delete backup copies from the document root (store them outside it), deny backup extensions at the web server, and rotate credentials found in the file.',
    };
  }
  if (/phpinfo|debug|trace\.axd|server-info/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-DEBUG-EXPOSED',
      title: (p) => `Debug endpoint exposed at ${p}`,
      description:
        'A debug/diagnostic endpoint is reachable and discloses internal configuration, paths, and versions useful for planning further attacks.',
      severity: 'MEDIUM',
      category: 'logging',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Disable debug endpoints in production (or restrict them to authenticated administrators on an internal network) and remove phpinfo-style pages.',
    };
  }
  if (/server-status/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-STATUS-EXPOSED',
      title: (p) => `Server-status page exposed at ${p}`,
      description:
        'The server-status page is reachable and discloses worker state, request URLs, and client addresses to unauthenticated visitors.',
      severity: 'MEDIUM',
      category: 'web',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Restrict server-status to localhost/administrators (`Require ip 127.0.0.1`) or disable the status module on public virtual hosts.',
    };
  }
  if (/swagger|openapi|api-docs|\/api\/docs/i.test(path)) {
    return {
      ruleId: 'API-DOCS-EXPOSED',
      title: (p) => `API documentation exposed at ${p}`,
      description:
        'Machine-readable API documentation is publicly reachable, giving attackers a complete endpoint and schema inventory to probe for authorization flaws.',
      severity: 'LOW',
      category: 'api',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Confirm public API docs are intentional; otherwise gate them behind authentication and strip internal/admin endpoints from public specs.',
    };
  }
  if (/\.ds_store($|[?#])/i.test(path)) {
    return {
      ruleId: 'SENSITIVE-DSSTORE-EXPOSED',
      title: (p) => `Directory listing file exposed at ${p}`,
      description:
        'A .DS_Store file is readable and reveals internal directory and file names, aiding targeted probing.',
      severity: 'LOW',
      category: 'web',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Delete .DS_Store files from deployed artifacts, add them to .gitignore/deploy exclusions, and deny dotfiles at the web server.',
    };
  }
  // Any other probe path: the tool probed it, but nothing in the evidence
  // confirms it is sensitive — no finding (Evidence First).
  return null;
}

function parseSensitivePaths(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  const drafts: DraftFinding[] = [];
  const seen = new Set<string>();
  for (const probe of collectProbes(evidence)) {
    if (!probe.exposed) continue;
    const rule = classifySensitivePath(probe.path);
    if (!rule) continue;
    const key = `${rule.ruleId}|${probe.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    drafts.push({
      ruleId: rule.ruleId,
      title: rule.title(probe.path),
      description: rule.description,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      owasp: rule.owasp,
      remediation: rule.remediation,
      evidence: { path: probe.path, status: probe.status },
    });
  }
  return drafts;
}

// ---------------------------------------------------------------------------
// Port parser
// ---------------------------------------------------------------------------

const DB_PORTS = new Map<number, string>([
  [1433, 'MSSQL'],
  [1521, 'Oracle'],
  [3306, 'MySQL'],
  [5432, 'PostgreSQL'],
  [6379, 'Redis'],
  [9200, 'Elasticsearch'],
  [11211, 'Memcached'],
  [27017, 'MongoDB'],
]);
const REMOTE_ADMIN_PORTS = new Map<number, string>([
  [22, 'SSH'],
  [3389, 'RDP'],
  [5900, 'VNC'],
  [5901, 'VNC'],
]);
/** Ordinary web ports: reachable is expected, never a finding. */
const IGNORed_WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 3000]);

function collectOpenPorts(evidence: Record<string, unknown>): Array<{ port: number; service: string | null }> {
  const raw = evidence['openPorts'] ?? evidence['ports'] ?? evidence['open_ports'];
  if (!Array.isArray(raw)) return [];
  const out: Array<{ port: number; service: string | null }> = [];
  for (const item of raw) {
    if (typeof item === 'number' && Number.isInteger(item) && item > 0 && item < 65536) {
      out.push({ port: item, service: null });
    } else if (isRecord(item)) {
      const port = item['port'];
      const state = item['state'];
      if (typeof port !== 'number' || !Number.isInteger(port) || port <= 0 || port >= 65536) continue;
      if (typeof state === 'string' && !/^(open|accessible|reachable)$/i.test(state)) continue;
      const service = item['service'];
      out.push({ port, service: typeof service === 'string' ? service : null });
    }
  }
  return out;
}

function parsePorts(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  const drafts: DraftFinding[] = [];
  const seen = new Set<number>();
  for (const { port, service } of collectOpenPorts(evidence)) {
    if (seen.has(port)) continue;
    seen.add(port);
    if (IGNORed_WEB_PORTS.has(port)) continue;
    const db = DB_PORTS.get(port);
    if (db) {
      drafts.push({
        ruleId: 'PORT-DB-EXPOSED',
        title: `Database port reachable: ${port} (${service ?? db})`,
        description: `A database service port (${port}, ${service ?? db}) accepts connections from the network. Databases must never be directly reachable from untrusted networks.`,
        severity: 'HIGH',
        category: 'storage',
        cwe: 'CWE-200',
        owasp: 'A05:2021',
        remediation:
          'Firewall the database port to application hosts only (security group / nftables), require authenticated encrypted connections, and verify no public port-forward exists.',
        evidence: { port, service: service ?? db },
      });
      continue;
    }
    if (port === 23) {
      drafts.push({
        ruleId: 'PORT-TELNET-EXPOSED',
        title: 'Telnet port reachable: 23',
        description:
          'Telnet (port 23) is reachable. Telnet transmits credentials and sessions in cleartext and must not be exposed.',
        severity: 'HIGH',
        category: 'web',
        cwe: 'CWE-319',
        owasp: 'A05:2021',
        remediation: 'Disable telnet; use SSH with key authentication instead.',
        evidence: { port },
      });
      continue;
    }
    if (port === 21) {
      drafts.push({
        ruleId: 'PORT-FTP-EXPOSED',
        title: 'FTP port reachable: 21',
        description:
          'FTP (port 21) is reachable. Classic FTP transmits credentials in cleartext and is frequently abused for anonymous access.',
        severity: 'MEDIUM',
        category: 'web',
        cwe: 'CWE-319',
        owasp: 'A05:2021',
        remediation: 'Disable FTP in favor of SFTP/FTPS, or restrict it to trusted networks with strong credentials.',
        evidence: { port },
      });
      continue;
    }
    const admin = REMOTE_ADMIN_PORTS.get(port);
    if (admin) {
      drafts.push({
        ruleId: 'PORT-REMOTE-ADMIN-EXPOSED',
        title: `Remote-admin port reachable: ${port} (${service ?? admin})`,
        description: `A remote-administration service (${service ?? admin}, port ${port}) is reachable from the network and will attract brute-force attacks.`,
        severity: 'MEDIUM',
        category: 'web',
        cwe: 'CWE-200',
        owasp: 'A05:2021',
        remediation:
          'Restrict the admin port to bastion/VPN source IPs, enforce key- or MFA-based authentication, and add brute-force rate limiting.',
        evidence: { port, service: service ?? admin },
      });
      continue;
    }
    // Other open ports (custom app ports, etc.): reachable is not by itself
    // confirmed sensitive — no finding (Evidence First).
  }
  return drafts;
}

// ---------------------------------------------------------------------------
// Verbose-error parser
// ---------------------------------------------------------------------------

function parseErrorDisclosure(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  if (evidence['errorDisclosure'] !== true && evidence['stackTraceExposed'] !== true) return [];
  const sample = evidence['errorSample'];
  return [
    {
      ruleId: 'ERROR-DISCLOSURE',
      title: 'Verbose error messages disclose internals',
      description:
        'The application returned a verbose error (stack trace or framework debug page) that discloses code paths, library versions, or configuration to callers.',
      severity: 'MEDIUM',
      category: 'logging',
      cwe: 'CWE-209',
      owasp: 'A05:2021',
      remediation:
        'Return generic error pages/messages to clients, log full details server-side only, and disable framework debug mode in production.',
      evidence: {
        sample: typeof sample === 'string' ? sample.slice(0, 500) : null,
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Normalize raw tool results into deduplicated, redacted findings.
 *
 * @param toolResults raw `ToolResult`s from the scan runner.
 * @param target the scan target these findings belong to (e.g. the target URL).
 * @returns confirmed findings sorted by ruleId/title; `[]` when nothing ran
 *          or nothing sensitive was confirmed.
 */
export function normalize(toolResults: ToolResult[], target: string): NormalizedFinding[] {
  const drafts: DraftFinding[] = [];
  for (const result of toolResults ?? []) {
    const parsed = ToolResultSchema.safeParse(result);
    if (!parsed.success) continue; // malformed tool output is never a finding
    if (parsed.data.status !== 'passed') continue; // failed/skipped: zero findings
    const evidence = parsed.data.evidence;
    if (evidence === null || evidence === undefined) continue;
    drafts.push(...parseTls(evidence));
    drafts.push(...parseHeaders(evidence));
    drafts.push(...parseSensitivePaths(evidence));
    drafts.push(...parsePorts(evidence));
    drafts.push(...parseErrorDisclosure(evidence));
  }

  const seen = new Set<string>();
  const findings: NormalizedFinding[] = [];
  for (const draft of drafts) {
    const fingerprint = fingerprintFor(target, draft.category, draft.ruleId, draft.title);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    findings.push({
      fingerprint,
      target,
      category: draft.category,
      ruleId: draft.ruleId,
      title: draft.title,
      description: draft.description,
      severity: draft.severity,
      cwe: draft.cwe,
      owasp: draft.owasp,
      evidence: redactSecrets(draft.evidence),
      remediation: draft.remediation,
      confidence: 'confirmed',
    });
  }
  findings.sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.title.localeCompare(b.title));
  return findings;
}
