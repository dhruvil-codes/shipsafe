/**
 * Explainer tests: every rule in the adapter RULE_CATALOG must have a
 * deterministic template with a copy-pasteable fix; unknown rules fall back
 * to the finding's own text (never invented vulnerabilities).
 */
import { describe, expect, it } from 'vitest';
import { RULE_CATALOG } from '@shipsafe/adapters';
import type { NormalizedFinding } from '@shipsafe/shared';
import { explain } from '../src/index';

let counter = 100;
function findingFor(ruleId: string): NormalizedFinding {
  counter += 1;
  const meta = RULE_CATALOG.find((r) => r.ruleId === ruleId);
  if (!meta) throw new Error(`unknown rule in test: ${ruleId}`);
  return {
    fingerprint: counter.toString(16).padStart(16, '0'),
    target: 'https://app.example.com',
    category: meta.category,
    ruleId: meta.ruleId,
    title: `${meta.label} (test)`,
    description: 'synthetic description',
    severity: meta.severity,
    cwe: meta.cwe,
    owasp: meta.owasp,
    evidence: {},
    remediation: 'synthetic remediation',
    confidence: 'confirmed',
  };
}

describe('explain', () => {
  it('covers every rule in RULE_CATALOG with what/why/fix/verify + code snippet', () => {
    expect(RULE_CATALOG.length).toBeGreaterThan(0);
    for (const meta of RULE_CATALOG) {
      const explanation = explain(findingFor(meta.ruleId));
      expect(explanation.what.length, `${meta.ruleId} what`).toBeGreaterThan(0);
      expect(explanation.why.length, `${meta.ruleId} why`).toBeGreaterThan(0);
      expect(explanation.fix.length, `${meta.ruleId} fix`).toBeGreaterThan(0);
      expect(explanation.verify.length, `${meta.ruleId} verify`).toBeGreaterThan(0);
      // Copy-pasteable: fix carries a fenced code/config snippet.
      expect(explanation.fix, `${meta.ruleId} fix snippet`).toContain('```');
    }
  });

  it('is deterministic for the same finding', () => {
    const finding = findingFor('HEADER-HSTS-MISSING');
    expect(explain(finding)).toEqual(explain({ ...finding }));
  });

  it('falls back to the finding text for unknown rule IDs without inventing', () => {
    const finding: NormalizedFinding = {
      ...findingFor('HEADER-HSTS-MISSING'),
      ruleId: 'FUTURE-RULE-999',
      title: 'Some future check',
      description: 'Future description.',
      remediation: 'Future remediation steps.',
    };
    const explanation = explain(finding);
    expect(explanation.what).toContain('Some future check');
    expect(explanation.what).toContain('Future description.');
    expect(explanation.fix).toBe('Future remediation steps.');
    expect(explanation.verify.length).toBeGreaterThan(0);
  });
});
