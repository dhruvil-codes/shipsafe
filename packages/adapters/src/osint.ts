/**
 * @shipsafe/adapters — OSINT & attack-surface normalizer.
 *
 * Parses evidence produced by `runner/osint_engine.py` (tool
 * `"osint-suite"`), which orchestrates the real binaries
 * subfinder, httpx, subzy, checkdmarc, and whois inside the InstaBox VM.
 *
 * Invariants (same as `normalize.ts`):
 * - Only `ToolResult`s with `status: 'passed'` can produce findings.
 * - Every finding needs confirmed evidence. A missing/unparseable section
 *   yields no finding — never a fabricated weakness.
 * - Parsers key off evidence *shape*, not the tool name.
 * - Evidence is redacted via `redactSecrets` before persistence.
 *
 * Expected evidence shape (see `runner/osint_engine.py`):
 * ```
 * {
 *   domain: "example.com",
 *   subfinder: { ran, argv, returncode, subdomains: string[], rawLines? },
 *   httpx:     { ran, argv, returncode, hosts: [{ host|input|url,
 *                status_code|status, title?, tech|technologies?, server? }] },
 *   subzy:    { ran, argv, returncode,
 *                results: [{ subdomain, service?, vulnerable?|status? }],
 *                raw?: string },
 *   checkdmarc: { ran, argv, returncode, parsed?: { dmarc?: { valid?,
 *                  policy?, location?, record? }, spf? }, raw? },
 *   whois:    { ran, argv, returncode, text?, registrar?,
 *                creationDate?, expiryDate?, daysUntilExpiry? }
 * }
 * ```
 * Every section carries `ran: false, error` when its binary was missing or
 * failed; such sections never produce findings.
 */
import { fingerprintFor, redactSecrets, type DraftFinding } from './primitives';
import type { RuleMeta } from './normalize';
import {
  ToolResultSchema,
  type NormalizedFinding,
  type ToolResult,
} from '@shipsafe/shared';

/** Rules this OSINT normalizer can emit (merged into RULE_CATALOG). */
export const OSINT_RULE_CATALOG: RuleMeta[] = [
  { ruleId: 'OSINT-DMARC-MISSING', label: 'Missing DMARC email authentication record', severity: 'HIGH', category: 'auth', cwe: 'CWE-358', owasp: 'A07:2021' },
  { ruleId: 'OSINT-DMARC-PERMISSIVE', label: 'Permissive DMARC policy (p=none)', severity: 'MEDIUM', category: 'auth', cwe: 'CWE-358', owasp: 'A07:2021' },
  { ruleId: 'OSINT-SUBDOMAIN-TAKEOVER', label: 'Subdomain takeover vulnerability', severity: 'CRITICAL', category: 'web', cwe: 'CWE-650', owasp: 'A05:2021' },
  { ruleId: 'OSINT-EXPOSED-STAGING', label: 'Exposed staging/dev environment', severity: 'MEDIUM', category: 'web', cwe: 'CWE-200', owasp: 'A05:2021' },
  { ruleId: 'OSINT-DOMAIN-EXPIRING', label: 'Domain registration expiring soon', severity: 'MEDIUM', category: 'logging', cwe: 'CWE-672' },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** A tool-evidence section only counts when its binary actually ran. */
function ranSection(evidence: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const section = evidence[key];
  if (!isRecord(section) || section['ran'] !== true) return null;
  return section;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function statusCodeOf(host: Record<string, unknown>): number | null {
  for (const key of ['status_code', 'statusCode', 'status', 'code']) {
    const value = host[key];
    if (typeof value === 'number' && Number.isInteger(value)) return value;
    if (typeof value === 'string' && /^\d{3}$/.test(value.trim())) return Number(value.trim());
  }
  return null;
}

function hostNameOf(host: Record<string, unknown>): string | null {
  for (const key of ['host', 'input', 'hostname', 'name', 'url']) {
    const value = host[key];
    if (typeof value !== 'string' || value.length === 0) continue;
    // httpx `input`/`url` may be a full URL — reduce to the hostname.
    const bare = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0] as string;
    const name = bare.split(':')[0] as string;
    if (name) return name.toLowerCase();
  }
  return null;
}

function techOf(host: Record<string, unknown>): string[] {
  const raw = host['tech'] ?? host['technologies'] ?? host['technology'];
  if (Array.isArray(raw)) return raw.filter((t): t is string => typeof t === 'string');
  if (typeof raw === 'string') return [raw];
  return [];
}

// ---------------------------------------------------------------------------
// checkdmarc parser (email spoofing)
// ---------------------------------------------------------------------------

function missingDraft(
  domain: string,
  observed: { valid: unknown; policy: unknown; record: unknown },
): DraftFinding {
  return {
    ruleId: 'OSINT-DMARC-MISSING',
    title: `Missing DMARC email authentication record (${domain})`,
    description: `The checkdmarc validator found no usable DMARC record for ${domain}. Without DMARC, attackers can send email that appears to come from this domain (exact-domain spoofing) and receivers have no owner-published policy to enforce.`,
    severity: 'HIGH',
    category: 'auth',
    cwe: 'CWE-358',
    owasp: 'A07:2021',
    remediation:
      'Publish a DMARC record in DNS that starts at monitoring and moves to enforcement:\n\n```dns\n' +
      `_dmarc.${domain}.  TXT  "v=DMARC1; p=reject; rua=mailto:security@${domain}; fo=1; adkim=s; aspf=s"\n` +
      '```\nStart with `p=quarantine` while reviewing aggregate reports, then move to `p=reject`.',
    evidence: { domain, valid: observed.valid, policy: observed.policy, record: observed.record },
  };
}

function parseDmarc(evidence: Record<string, unknown>): DraftFinding[] {
  const section = ranSection(evidence, 'checkdmarc');
  if (!section) return [];
  const parsed = section['parsed'];
  if (!isRecord(parsed)) return [];
  const domain = asString(evidence['domain']) ?? asString(parsed['domain']) ?? 'the domain';
  const rawDmarc = parsed['dmarc'];
  // checkdmarc ran and explicitly reports no DMARC object: confirmed missing.
  if (rawDmarc === null) {
    return [missingDraft(domain, { valid: false, policy: null, record: null })];
  }
  // checkdmarc nests results under `dmarc` (and `spf`); accept a flat record too.
  // The library shape carries the policy in `tags.p.value`, not `policy`.
  const dmarc = isRecord(rawDmarc) ? (rawDmarc as Record<string, unknown>) : parsed;
  if (dmarc['record'] === undefined && dmarc['valid'] === undefined && dmarc['policy'] === undefined) {
    return [];
  }
  const tags = isRecord(dmarc['tags']) ? (dmarc['tags'] as Record<string, unknown>) : {};
  const tagP = isRecord(tags['p']) ? (tags['p'] as Record<string, unknown>) : {};
  const tagPolicy = typeof tagP['value'] === 'string' ? (tagP['value'] as string).toLowerCase() : null;
  const policy =
    typeof dmarc['policy'] === 'string' ? dmarc['policy'].toLowerCase() : tagPolicy;
  const valid = dmarc['valid'];
  const location = dmarc['location'];

  if (valid === false || location === null || (location === undefined && policy === null && dmarc['record'] == null)) {
    return [missingDraft(domain, { valid: valid ?? null, policy, record: dmarc['record'] ?? null })];
  }
  if (policy === 'none') {
    return [
      {
        ruleId: 'OSINT-DMARC-PERMISSIVE',
        title: `Permissive DMARC policy on ${domain} (p=none)`,
        description: `The DMARC record for ${domain} publishes policy p=none, which only monitors: receivers take no action on mail that fails SPF/DKIM alignment, so spoofed messages are still delivered.`,
        severity: 'MEDIUM',
        category: 'auth',
        cwe: 'CWE-358',
        owasp: 'A07:2021',
        remediation:
          'Tighten the published policy toward enforcement once legitimate senders are aligned:\n\n```dns\n_dmarc.${domain}.  TXT  "v=DMARC1; p=quarantine; pct=100; rua=mailto:security@${domain}"\n```\nThen graduate to `p=reject` and keep monitoring `rua` aggregate reports.',
        evidence: { domain, policy, record: dmarc['record'] ?? null },
      },
    ];
  }
  return [];
}

// ---------------------------------------------------------------------------
// subzy parser (subdomain takeover)
// ---------------------------------------------------------------------------

const TAKEOVER_STATUS = /^(vulnerable|unclaimed|takeover|claimable|nxdomain_unclaimed)$/i;

function parseTakeover(evidence: Record<string, unknown>, domain: string): DraftFinding[] {
  const section = ranSection(evidence, 'subzy');
  if (!section) return [];
  const drafts: DraftFinding[] = [];
  const seen = new Set<string>();
  const push = (subdomain: string, service: string | null, extra: Record<string, unknown>) => {
    const name = subdomain.toLowerCase();
    if (!name.endsWith(`.${domain}`) && name !== domain) return;
    const key = `${name}|${service ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    drafts.push({
      ruleId: 'OSINT-SUBDOMAIN-TAKEOVER',
      title: `Subdomain takeover vulnerability on ${name}`,
      description: `The subdomain ${name} has a dangling DNS record pointing at the unclaimed ${service ?? 'third-party'} service. An attacker can claim that service endpoint and serve attacker-controlled content under your domain (credential phishing, cookie theft on sibling subdomains).`,
      severity: 'CRITICAL',
      category: 'web',
      cwe: 'CWE-650',
      owasp: 'A05:2021',
      remediation:
        'Reclaim or remove the dangling record immediately:\n\n```bash\n# either claim the endpoint at the provider, or delete the record\ndig +short CNAME ${name}\n# remove the CNAME/A record from the zone, then re-run the ShipSafe scan\n```',
      evidence: { subdomain: name, service, ...extra },
    });
  };

  const results = section['results'];
  if (Array.isArray(results)) {
    for (const item of results) {
      if (!isRecord(item)) continue;
      const subdomain = asString(item['subdomain'] ?? item['host'] ?? item['target']);
      if (!subdomain) continue;
      const service = asString(item['service'] ?? item['engine'] ?? item['provider']);
      const status = asString(item['status']);
      if (item['vulnerable'] === true || (status !== null && TAKEOVER_STATUS.test(status))) {
        push(subdomain, service, {
          status: status ?? (item['vulnerable'] === true ? 'vulnerable' : null),
          httpStatus: typeof item['http_status'] === 'number' ? item['http_status'] : (typeof item['httpStatus'] === 'number' ? item['httpStatus'] : null),
        });
      }
    }
  }
  // Raw-text fallback: subzy prints one line per target; a line is evidence of
  // takeover only when it names a subdomain of the target AND carries an
  // explicit vulnerability marker.
  const raw = section['raw'];
  if (typeof raw === 'string' && raw.length > 0) {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const lineRe = new RegExp(`([a-z0-9_.-]+\\.${escaped})`, 'gi');
    for (const line of raw.split('\n')) {
      if (!/vulnerab|takeover|not found|no such|unclaimed/i.test(line)) continue;
      lineRe.lastIndex = 0;
      const match = lineRe.exec(line);
      if (!match?.[1]) continue;
      const serviceMatch = /\[([^\]]+)\]|service[:\s]+([a-z0-9 _-]+)/i.exec(line);
      push(match[1], (serviceMatch?.[1] ?? serviceMatch?.[2] ?? null)?.trim() || null, { rawLine: line.slice(0, 300) });
    }
  }
  return drafts;
}

// ---------------------------------------------------------------------------
// subfinder + httpx parser (exposed staging / dev)
// ---------------------------------------------------------------------------

/** Leftmost-label match only: staging.<domain>, dev-1.<domain>, admin.<domain>. */
const STAGING_LABEL = /^(staging|stage|dev|development|test|testing|qa|uat|sandbox|demo|beta|preview|canary|admin|internal|intranet)([.-].*)?$/i;

function leftmostLabel(subdomain: string, domain: string): string | null {
  const name = subdomain.toLowerCase();
  if (name === domain) return null;
  if (!name.endsWith(`.${domain}`)) return null;
  return name.slice(0, name.length - domain.length - 1).split('.')[0] ?? null;
}

function parseStaging(evidence: Record<string, unknown>, domain: string): DraftFinding[] {
  const httpx = ranSection(evidence, 'httpx');
  if (!httpx) return [];
  const hosts = httpx['hosts'];
  if (!Array.isArray(hosts)) return [];
  const drafts: DraftFinding[] = [];
  const seen = new Set<string>();
  for (const item of hosts) {
    if (!isRecord(item)) continue;
    const name = hostNameOf(item);
    if (!name) continue;
    const label = leftmostLabel(name, domain);
    if (!label || !STAGING_LABEL.test(label)) continue;
    // Only a live (2xx) response confirms an exposed environment; anything
    // else (redirect, auth challenge, 404) is not confirmed exposure.
    const code = statusCodeOf(item);
    if (code === null || code < 200 || code >= 300) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    drafts.push({
      ruleId: 'OSINT-EXPOSED-STAGING',
      title: `Exposed staging environment (${name})`,
      description: `The staging/dev-style subdomain ${name} answers with HTTP ${code} and appears to serve content without failing closed. Non-production environments frequently carry weaker credentials, debug endpoints, and production data copies.`,
      severity: 'MEDIUM',
      category: 'web',
      cwe: 'CWE-200',
      owasp: 'A05:2021',
      remediation:
        'Remove the exposure or gate it:\n\n```bash\n# restrict to office/VPN ranges or add authentication,\n# or remove the DNS record if the environment is retired\ndig +short ${name}\n```\nVerify with `curl -sI https://${name}` from an untrusted network after the change.',
      evidence: {
        subdomain: name,
        url: asString(item['url']) ?? `https://${name}`,
        statusCode: code,
        title: asString(item['title']),
        tech: techOf(item),
        server: asString(item['server']),
      },
    });
  }
  return drafts;
}

// ---------------------------------------------------------------------------
// whois parser (domain expiry)
// ---------------------------------------------------------------------------

const EXPIRY_SOON_DAYS = 30;

function daysUntil(section: Record<string, unknown>): number | null {
  const direct = section['daysUntilExpiry'] ?? section['days_until_expiry'];
  if (typeof direct === 'number' && Number.isFinite(direct)) return Math.floor(direct);
  const raw = section['expiryDate'] ?? section['expiry_date'] ?? section['expiresAt'];
  if (typeof raw !== 'string') return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return null;
  return Math.floor((date.getTime() - Date.now()) / 86_400_000);
}

function parseExpiry(evidence: Record<string, unknown>, domain: string): DraftFinding[] {
  const section = ranSection(evidence, 'whois');
  if (!section) return [];
  const days = daysUntil(section);
  if (days === null || days > EXPIRY_SOON_DAYS) return [];
  const expired = days < 0;
  return [
    {
      ruleId: 'OSINT-DOMAIN-EXPIRING',
      title: expired
        ? `Domain registration expired for ${domain}`
        : `Domain registration expiring soon for ${domain} (${days} days)`,
      description: expired
        ? `WHOIS shows the registration for ${domain} has lapsed. An expired domain can be re-registered by anyone, enabling full impersonation of the service.`
        : `WHOIS shows the registration for ${domain} expires in ${days} days. If renewal fails (dead contact, failed payment), the domain lapses and can be claimed by attackers.`,
      severity: 'MEDIUM',
      category: 'logging',
      cwe: 'CWE-672',
      remediation:
        'Renew now and prevent recurrence:\n\n```bash\n# renew at your registrar, then enable auto-renew + registry lock\nwhois ${domain} | grep -i expir\n```\nConfirm the new expiry date in WHOIS and enable registrar auto-renew with a monitored billing contact.',
      evidence: {
        domain,
        registrar: asString(section['registrar']),
        expiryDate: asString(section['expiryDate'] ?? section['expiry_date'] ?? section['expiresAt']),
        daysUntilExpiry: days,
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/**
 * Parse one osint-suite evidence object into draft findings.
 * Returns `[]` when the evidence carries no confirmed weakness.
 */
export function parseOsintEvidence(evidence: unknown): DraftFinding[] {
  if (!isRecord(evidence)) return [];
  const domain = asString(evidence['domain']);
  if (!domain) return [];
  return [
    ...parseDmarc(evidence),
    ...parseTakeover(evidence, domain.toLowerCase()),
    ...parseStaging(evidence, domain.toLowerCase()),
    ...parseExpiry(evidence, domain.toLowerCase()),
  ];
}

function finalize(drafts: DraftFinding[], target: string): NormalizedFinding[] {
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
      ...(draft.owasp ? { owasp: draft.owasp } : {}),
      evidence: redactSecrets(draft.evidence),
      remediation: draft.remediation,
      confidence: 'confirmed',
    });
  }
  findings.sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.title.localeCompare(b.title));
  return findings;
}

/**
 * Normalize raw tool results into deduplicated, redacted OSINT findings.
 * Only `status: 'passed'` results are considered; anything else yields zero
 * findings. This is the `normalizeAll` participant for the OSINT engine: the
 * main `normalize()` aggregator also invokes `parseOsintEvidence`, so OSINT
 * evidence is covered whichever entry point the orchestrator uses.
 */
export function normalizeOsint(toolResults: ToolResult[], target: string): NormalizedFinding[] {
  const drafts: DraftFinding[] = [];
  for (const result of toolResults ?? []) {
    const parsed = ToolResultSchema.safeParse(result);
    if (!parsed.success) continue;
    if (parsed.data.status !== 'passed') continue;
    if (parsed.data.evidence === null || parsed.data.evidence === undefined) continue;
    drafts.push(...parseOsintEvidence(parsed.data.evidence));
  }
  return finalize(drafts, target);
}
