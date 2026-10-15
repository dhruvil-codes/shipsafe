/**
 * Normalizer tests: every fixture in tests/fixtures is consumed here
 * (100% fixture coverage). Failed/skipped tools must yield zero findings.
 */
import { describe, expect, it } from 'vitest';
import { NormalizedFindingSchema, type ToolResult } from '@shipsafe/shared';
import { fingerprintFor, normalize } from '../src/index';
import errorWithSecrets from './fixtures/error-with-secrets.json';
import failedTool from './fixtures/failed-tool.json';
import headersHealthy from './fixtures/headers-healthy.json';
import headersMissing from './fixtures/headers-missing.json';
import portsClean from './fixtures/ports-clean.json';
import portsOpen from './fixtures/ports-open.json';
import sensitiveClean from './fixtures/sensitive-clean.json';
import sensitiveEnvExposed from './fixtures/sensitive-env-exposed.json';
import skippedTool from './fixtures/skipped-tool.json';
import tlsExpired from './fixtures/tls-expired.json';
import tlsHealthy from './fixtures/tls-healthy.json';
import tlsWeak from './fixtures/tls-weak.json';

interface Fixture {
  target: string;
  toolResults: ToolResult[];
}

function run(fixture: Fixture) {
  return normalize(fixture.toolResults, fixture.target);
}

function ruleIdsOf(fixture: Fixture): string[] {
  return run(fixture).map((f) => f.ruleId);
}

describe('tls evidence', () => {
  it('flags an expired certificate as HIGH CWE-295', () => {
    const findings = run(tlsExpired as Fixture);
    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding?.ruleId).toBe('TLS-CERT-EXPIRED');
    expect(finding?.severity).toBe('HIGH');
    expect(finding?.cwe).toBe('CWE-295');
    expect(finding?.category).toBe('web');
    expect(finding?.confidence).toBe('confirmed');
  });

  it('flags deprecated protocols and weak ciphers', () => {
    const ids = ruleIdsOf(tlsWeak as Fixture);
    expect(ids.filter((id) => id === 'TLS-PROTOCOL-DEPRECATED')).toHaveLength(2);
    expect(ids).toContain('TLS-CIPHER-WEAK');
    const cipher = run(tlsWeak as Fixture).find((f) => f.ruleId === 'TLS-CIPHER-WEAK');
    expect(cipher?.severity).toBe('MEDIUM');
  });

  it('produces zero findings for a healthy tls fixture', () => {
    expect(run(tlsHealthy as Fixture)).toHaveLength(0);
  });
});

describe('header evidence', () => {
  it('maps missing HSTS/CSP to CWE-319/CWE-693 under OWASP A05', () => {
    const findings = run(headersMissing as Fixture);
    const byId = new Map(findings.map((f) => [f.ruleId + '|' + f.title, f]));
    const hsts = findings.find((f) => f.ruleId === 'HEADER-HSTS-MISSING');
    expect(hsts?.severity).toBe('MEDIUM');
    expect(hsts?.cwe).toBe('CWE-319');
    expect(hsts?.owasp).toBe('A05:2021');
    const csp = findings.find((f) => f.ruleId === 'HEADER-CSP-MISSING');
    expect(csp?.severity).toBe('MEDIUM');
    expect(csp?.cwe).toBe('CWE-693');
    expect(byId.size).toBeGreaterThan(0);
  });

  it('flags wildcard CORS with credentials, cookie flags, and version banners', () => {
    const ids = ruleIdsOf(headersMissing as Fixture);
    expect(ids).toContain('CORS-WILDCARD-CREDENTIALS');
    expect(ids).toContain('COOKIE-NO-SECURE');
    expect(ids).toContain('COOKIE-NO-HTTPONLY');
    expect(ids).toContain('COOKIE-NO-SAMESITE');
    expect(ids.filter((id) => id === 'HEADER-VERSION-DISCLOSURE')).toHaveLength(2);
    expect(ids).toContain('HEADER-REFERRER-MISSING');
    const cors = run(headersMissing as Fixture).find((f) => f.ruleId === 'CORS-WILDCARD-CREDENTIALS');
    expect(cors?.severity).toBe('HIGH');
    expect(cors?.category).toBe('api');
  });

  it('produces zero findings for a hardened header fixture', () => {
    expect(run(headersHealthy as Fixture)).toHaveLength(0);
  });
});

describe('sensitive-path evidence', () => {
  it('flags exposed .env as CRITICAL CWE-538 (and only confirmed paths)', () => {
    const findings = run(sensitiveEnvExposed as Fixture);
    expect(findings.map((f) => f.ruleId).sort()).toEqual([
      'SENSITIVE-BACKUP-EXPOSED',
      'SENSITIVE-ENV-EXPOSED',
      'SENSITIVE-GIT-EXPOSED',
    ]);
    const env = findings.find((f) => f.ruleId === 'SENSITIVE-ENV-EXPOSED');
    expect(env?.severity).toBe('CRITICAL');
    expect(env?.cwe).toBe('CWE-538');
    expect(env?.category).toBe('source');
  });

  it('ignores 404/403 probes and unclassified exposed paths', () => {
    expect(run(sensitiveClean as Fixture)).toHaveLength(0);
  });
});

describe('port evidence', () => {
  it('flags database, telnet, and remote-admin ports (not plain web ports)', () => {
    const findings = run(portsOpen as Fixture);
    expect(findings.map((f) => f.ruleId).sort()).toEqual([
      'PORT-DB-EXPOSED',
      'PORT-DB-EXPOSED',
      'PORT-REMOTE-ADMIN-EXPOSED',
      'PORT-TELNET-EXPOSED',
    ]);
    const db = findings.find((f) => f.ruleId === 'PORT-DB-EXPOSED');
    expect(db?.severity).toBe('HIGH');
    expect(db?.category).toBe('storage');
  });

  it('produces zero findings for web-only ports', () => {
    expect(run(portsClean as Fixture)).toHaveLength(0);
  });
});

describe('no credit for unrun tools', () => {
  it('failed tool results produce zero findings despite suggestive evidence', () => {
    expect(run(failedTool as Fixture)).toHaveLength(0);
  });

  it('skipped tool results produce zero findings despite expired-cert evidence', () => {
    expect(run(skippedTool as Fixture)).toHaveLength(0);
  });

  it('malformed tool results are ignored, never findings', () => {
    expect(normalize([{ nope: true }] as unknown as ToolResult[], 'https://x.example')).toHaveLength(0);
    expect(normalize([], 'https://x.example')).toHaveLength(0);
  });
});

describe('fingerprints and dedup', () => {
  it('fingerprintFor is a stable 16-char hex of target|category|ruleId|title', () => {
    const fp = fingerprintFor('https://a.example', 'web', 'R', 'T');
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    expect(fingerprintFor('https://a.example', 'web', 'R', 'T')).toBe(fp);
    expect(fingerprintFor('https://b.example', 'web', 'R', 'T')).not.toBe(fp);
  });

  it('duplicate tool results do not duplicate findings', () => {
    const fixture = headersMissing as Fixture;
    const once = normalize(fixture.toolResults, fixture.target);
    const twice = normalize([...fixture.toolResults, ...fixture.toolResults], fixture.target);
    expect(twice).toHaveLength(once.length);
    expect(once.length).toBeGreaterThan(0);
  });

  it('every emitted finding validates against NormalizedFindingSchema', () => {
    const all = [
      tlsExpired,
      tlsWeak,
      headersMissing,
      sensitiveEnvExposed,
      portsOpen,
      errorWithSecrets,
    ].flatMap((fx) => run(fx as Fixture));
    expect(all.length).toBeGreaterThan(0);
    for (const finding of all) {
      expect(NormalizedFindingSchema.safeParse(finding).success).toBe(true);
    }
  });
});

describe('secret redaction in persisted evidence', () => {
  it('redacts tokens, cookies, and credentials from error samples', () => {
    const findings = run(errorWithSecrets as Fixture);
    expect(findings.map((f) => f.ruleId)).toEqual(['ERROR-DISCLOSURE']);
    const sample = JSON.stringify(findings[0]?.evidence);
    expect(sample).not.toContain('sk-live-abc123');
    expect(sample).not.toContain('s3cr3t-value');
    expect(sample).not.toContain('supersecret');
    expect(sample).not.toContain('eyJhbGciOi');
    expect(sample).toContain('[REDACTED]');
  });
});
