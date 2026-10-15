/**
 * OSINT normalizer tests: every osint fixture in tests/fixtures is consumed
 * here. Only `status: 'passed'` results with confirmed evidence yield
 * findings; missing/unran sections are never findings.
 */
import { describe, expect, it } from 'vitest';
import { NormalizedFindingSchema, type ToolResult } from '@shipsafe/shared';
import { normalize, normalizeOsint, OSINT_RULE_CATALOG } from '../src/index';
import osintClean from './fixtures/osint-clean.json';
import osintMixed from './fixtures/osint-mixed.json';
import osintPartial from './fixtures/osint-partial.json';

interface Fixture {
  target: string;
  toolResults: ToolResult[];
}

function run(fixture: Fixture) {
  return normalizeOsint(fixture.toolResults, fixture.target);
}

describe('osint catalog', () => {
  it('exposes the five documented OSINT rules', () => {
    expect(OSINT_RULE_CATALOG.map((r) => r.ruleId).sort()).toEqual(
      [
        'OSINT-DMARC-MISSING',
        'OSINT-DMARC-PERMISSIVE',
        'OSINT-DOMAIN-EXPIRING',
        'OSINT-EXPOSED-STAGING',
        'OSINT-SUBDOMAIN-TAKEOVER',
      ].sort(),
    );
  });
});

describe('dmarc evidence', () => {
  it('flags a missing DMARC record as HIGH CWE-358', () => {
    const findings = run(osintMixed as Fixture);
    const dmarc = findings.find((f) => f.ruleId === 'OSINT-DMARC-MISSING');
    expect(dmarc).toBeDefined();
    expect(dmarc?.severity).toBe('HIGH');
    expect(dmarc?.cwe).toBe('CWE-358');
    expect(dmarc?.category).toBe('auth');
    expect(dmarc?.confidence).toBe('confirmed');
    expect(dmarc?.remediation).toContain('p=reject');
  });

  it('flags p=none as MEDIUM and an enforcing policy as clean', () => {
    const permissive = run(osintPartial as Fixture).find((f) => f.ruleId === 'OSINT-DMARC-PERMISSIVE');
    expect(permissive?.severity).toBe('MEDIUM');
    const clean = run(osintClean as Fixture);
    expect(clean.some((f) => f.ruleId.startsWith('OSINT-DMARC'))).toBe(false);
  });
});

describe('takeover evidence', () => {
  it('flags a vulnerable subzy result as CRITICAL CWE-650', () => {
    const findings = run(osintMixed as Fixture);
    const takeover = findings.find((f) => f.ruleId === 'OSINT-SUBDOMAIN-TAKEOVER');
    expect(takeover).toBeDefined();
    expect(takeover?.severity).toBe('CRITICAL');
    expect(takeover?.cwe).toBe('CWE-650');
    expect(takeover?.title).toContain('assets.example-test.invalid');
  });

  it('ignores non-vulnerable subzy results', () => {
    const clean = run(osintClean as Fixture);
    expect(clean.some((f) => f.ruleId === 'OSINT-SUBDOMAIN-TAKEOVER')).toBe(false);
  });
});

describe('staging evidence', () => {
  it('flags a live staging subdomain as MEDIUM CWE-200', () => {
    const staging = run(osintMixed as Fixture).find((f) => f.ruleId === 'OSINT-EXPOSED-STAGING');
    expect(staging).toBeDefined();
    expect(staging?.severity).toBe('MEDIUM');
    expect(staging?.title).toContain('staging.example-test.invalid');
  });

  it('does not flag production hostnames', () => {
    const clean = run(osintClean as Fixture);
    expect(clean.some((f) => f.ruleId === 'OSINT-EXPOSED-STAGING')).toBe(false);
  });
});

describe('whois evidence', () => {
  it('flags a domain expiring within 30 days', () => {
    const expiring = run(osintPartial as Fixture).find((f) => f.ruleId === 'OSINT-DOMAIN-EXPIRING');
    expect(expiring).toBeDefined();
    expect(expiring?.severity).toBe('MEDIUM');
    expect(expiring?.cwe).toBe('CWE-672');
  });

  it('passes a domain with distant expiry', () => {
    const clean = run(osintClean as Fixture);
    expect(clean.some((f) => f.ruleId === 'OSINT-DOMAIN-EXPIRING')).toBe(false);
  });
});

describe('osint invariants', () => {
  it('yields zero findings for a clean osint result', () => {
    expect(run(osintClean as Fixture)).toHaveLength(0);
  });

  it('yields zero findings when the tool result failed or was skipped', () => {
    const base = (osintMixed as Fixture).toolResults[0] as ToolResult;
    for (const status of ['failed', 'skipped'] as const) {
      expect(normalizeOsint([{ ...base, status }], (osintMixed as Fixture).target)).toHaveLength(0);
    }
  });

  it('sections whose binary did not run never produce findings', () => {
    // osint-partial ran only checkdmarc + whois: exactly those two findings.
    const ids = run(osintPartial as Fixture).map((f) => f.ruleId).sort();
    expect(ids).toEqual(['OSINT-DMARC-PERMISSIVE', 'OSINT-DOMAIN-EXPIRING'].sort());
  });

  it('matches the mixed fixture through the main normalize() aggregator', () => {
    const viaMain = normalize((osintMixed as Fixture).toolResults, (osintMixed as Fixture).target);
    const viaOsint = run(osintMixed as Fixture);
    expect(viaMain.map((f) => f.ruleId).sort()).toEqual(viaOsint.map((f) => f.ruleId).sort());
    expect(viaMain).toHaveLength(3);
  });

  it('every emitted finding validates against NormalizedFindingSchema', () => {
    for (const finding of run(osintMixed as Fixture)) {
      expect(NormalizedFindingSchema.safeParse(finding).success).toBe(true);
    }
  });
});
