/**
 * @shipsafe/adapters — shared primitives for normalizers.
 *
 * `fingerprintFor`, `redactSecrets`, and the internal `DraftFinding` shape
 * live here (instead of `normalize.ts`) so every parser module
 * (`normalize.ts`, `osint.ts`, future engines) can share them with a
 * strictly one-directional import graph and no module cycles:
 * parsers import from `./primitives`; nothing imports parsers except the
 * aggregator in `normalize.ts` and the public barrel in `index.ts`.
 */
import { createHash } from 'node:crypto';
import type { FindingCategory, Severity } from '@shipsafe/shared';

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

/**
 * An un-finalized finding produced by a parser. The aggregator
 * (`normalize()` / `normalizeOsint()`) assigns the fingerprint, redacts the
 * evidence, and de-duplicates before returning `NormalizedFinding`s.
 */
export interface DraftFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  cwe: string;
  /** OWASP Top 10 reference. Omitted when no Top 10 category honestly applies. */
  owasp?: string;
  remediation: string;
  evidence: unknown;
}
