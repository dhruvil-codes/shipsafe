/**
 * Scoring v1.0 tests: weights, deductions, critical cap, coverage, grades.
 * Every fixture in tests/fixtures is consumed here (100% fixture coverage).
 */
import { describe, expect, it } from 'vitest';
import type { NormalizedFinding } from '@shipsafe/shared';
import {
  CRITICAL_BANNER,
  computeScore,
  gradeFor,
} from '../src/index';
import cleanScan from './fixtures/clean-scan.json';
import criticalScan from './fixtures/critical-scan.json';
import emptyScan from './fixtures/empty-scan.json';
import mixedScan from './fixtures/mixed-scan.json';

interface ScanFixture {
  name: string;
  assessedControls: number;
  applicableControls: number;
  findings: NormalizedFinding[];
}

let counter = 0;
function makeFinding(
  category: NormalizedFinding['category'],
  severity: NormalizedFinding['severity'],
  confidence: NormalizedFinding['confidence'] = 'confirmed',
): NormalizedFinding {
  counter += 1;
  return {
    fingerprint: counter.toString(16).padStart(16, '0'),
    target: 'https://app.example.com',
    category,
    ruleId: 'TEST-RULE',
    title: `Test ${category} ${severity} ${counter}`,
    description: 'synthetic',
    severity,
    evidence: {},
    remediation: 'fix it',
    confidence,
  };
}

describe('computeScore on fixtures', () => {
  it('mixed scan: renormalized weighted average (auth 80, api 92, web 98 -> 88 B, 60 coverage)', () => {
    const fx = mixedScan as ScanFixture;
    const score = computeScore(fx.findings, fx.assessedControls, fx.applicableControls);
    expect(score.categoryScores).toEqual({ auth: 80, api: 92, web: 98 });
    expect(score.overall).toBe(88);
    expect(score.grade).toBe('B');
    expect(score.coverage).toBe(60);
    expect(score.capped).toBe(false);
    expect(score.banner).toBeUndefined();
    expect(score.scoringVersion).toBe('v1.0');
  });

  it('clean scan: 100 A with full coverage', () => {
    const fx = cleanScan as ScanFixture;
    const score = computeScore(fx.findings, fx.assessedControls, fx.applicableControls);
    expect(score.overall).toBe(100);
    expect(score.grade).toBe('A');
    expect(score.coverage).toBe(100);
    expect(score.capped).toBe(false);
  });

  it('empty scan: nothing assessed earns nothing (0 F, 0 coverage)', () => {
    const fx = emptyScan as ScanFixture;
    const score = computeScore(fx.findings, fx.assessedControls, fx.applicableControls);
    expect(score.overall).toBe(0);
    expect(score.grade).toBe('F');
    expect(score.coverage).toBe(0);
    expect(score.categoryScores).toEqual({});
  });

  it('critical scan: confirmed CRITICAL caps overall at 40 with banner', () => {
    const fx = criticalScan as ScanFixture;
    const score = computeScore(fx.findings, fx.assessedControls, fx.applicableControls);
    // source would be 60 without the cap; cap wins.
    expect(score.categoryScores).toEqual({ source: 60 });
    expect(score.overall).toBe(40);
    expect(score.capped).toBe(true);
    expect(score.banner).toBe(CRITICAL_BANNER);
  });
});

describe('weights and deductions', () => {
  it('renormalizes weights over assessed categories only', () => {
    // logging alone (weight 10): 100 - 8 = 92, no dilution from other categories.
    const score = computeScore([makeFinding('logging', 'MEDIUM')], 5, 10);
    expect(score.categoryScores).toEqual({ logging: 92 });
    expect(score.overall).toBe(92);
  });

  it('weights auth 25 / web 10 in a two-category average', () => {
    const score = computeScore(
      [makeFinding('auth', 'HIGH'), makeFinding('web', 'MEDIUM')],
      10,
      10,
    );
    // (80*25 + 92*10) / 35 = 83.43 -> 83
    expect(score.overall).toBe(83);
  });

  it('applies CRITICAL 40 / HIGH 20 / MEDIUM 8 / LOW 2 / INFO 0 and floors at 0', () => {
    const score = computeScore(
      [
        makeFinding('auth', 'HIGH'),
        makeFinding('auth', 'HIGH'),
        makeFinding('auth', 'HIGH'),
        makeFinding('auth', 'HIGH'),
        makeFinding('auth', 'HIGH'),
        makeFinding('web', 'INFO'),
      ],
      10,
      10,
    );
    expect(score.categoryScores).toEqual({ auth: 0, web: 100 });
    // (0*25 + 100*10) / 35 = 28.57 -> 29
    expect(score.overall).toBe(29);
    expect(score.grade).toBe('F');
  });
});

describe('critical cap', () => {
  it('caps an otherwise high score at 40', () => {
    const findings = [
      makeFinding('source', 'CRITICAL'),
      makeFinding('web', 'LOW'),
    ];
    const score = computeScore(findings, 10, 10);
    expect(score.overall).toBe(40);
    expect(score.capped).toBe(true);
    expect(score.banner).toBe(CRITICAL_BANNER);
  });

  it('does not cap for suspected (unconfirmed) criticals', () => {
    const score = computeScore([makeFinding('source', 'CRITICAL', 'suspected')], 10, 10);
    expect(score.overall).toBe(100);
    expect(score.capped).toBe(false);
  });
});

describe('coverage', () => {
  it('rounds to 1 decimal and handles edge cases', () => {
    expect(computeScore([], 1, 3).coverage).toBe(33.3);
    expect(computeScore([], 2, 3).coverage).toBe(66.7);
    expect(computeScore([], 5, 0).coverage).toBe(0);
    expect(computeScore([], 30, 20).coverage).toBe(100);
  });
});

describe('grades', () => {
  it('follows the >=90 A, >=70 B, >=50 C, else F bands', () => {
    expect(gradeFor(100)).toBe('A');
    expect(gradeFor(90)).toBe('A');
    expect(gradeFor(89)).toBe('B');
    expect(gradeFor(70)).toBe('B');
    expect(gradeFor(69)).toBe('C');
    expect(gradeFor(50)).toBe('C');
    expect(gradeFor(49)).toBe('F');
    expect(gradeFor(0)).toBe('F');
  });

  it('reaches C through accumulated non-critical penalties', () => {
    const findings = [
      makeFinding('auth', 'HIGH'),
      makeFinding('auth', 'HIGH'),
      makeFinding('auth', 'HIGH'),
      makeFinding('api', 'HIGH'),
      makeFinding('api', 'HIGH'),
      makeFinding('source', 'HIGH'),
    ];
    // auth 40, api 60, source 80; weights 25+20+20=65
    // (1000+1200+1600)/65 = 58.46 -> 58 C
    const score = computeScore(findings, 20, 20);
    expect(score.overall).toBe(58);
    expect(score.grade).toBe('C');
  });
});
