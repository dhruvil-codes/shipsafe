/**
 * Contract tests for @shipsafe/shared schemas.
 * Every fixture in tests/fixtures is consumed here (100% fixture coverage).
 */
import { describe, expect, it } from 'vitest';
import {
  NormalizedFindingSchema,
  ScanEventSchema,
  ScanManifestSchema,
  SecurityScoreSchema,
  ToolResultSchema,
  type ToolResult,
} from '../src/index';
import eventValid from './fixtures/event-valid.json';
import findingInvalid from './fixtures/finding-invalid.json';
import findingValid from './fixtures/finding-valid.json';
import manifestInvalid from './fixtures/manifest-invalid.json';
import manifestValid from './fixtures/manifest-valid.json';
import scoreValid from './fixtures/score-valid.json';

const BASE_TOOL_RESULT = {
  tool: 'headers',
  toolVersion: '1.0.0',
  status: 'passed',
  startedAt: '2026-10-15T00:00:00.000Z',
  endedAt: '2026-10-15T00:00:05.000Z',
  durationMs: 5000,
  checksAttempted: 8,
  evidence: { headers: {} },
} satisfies ToolResult;

describe('ScanManifestSchema', () => {
  it('accepts the valid manifest fixture', () => {
    expect(ScanManifestSchema.safeParse(manifestValid).success).toBe(true);
  });

  it('rejects the invalid manifest fixture (bad url, profile, dates)', () => {
    const result = ScanManifestSchema.safeParse(manifestInvalid);
    expect(result.success).toBe(false);
  });

  it('rejects each profile outside the enum', () => {
    for (const profile of ['portscan', 'zap', '']) {
      expect(
        ScanManifestSchema.safeParse({ ...manifestValid, profile }).success,
      ).toBe(false);
    }
  });
});

describe('ToolResultSchema', () => {
  it('accepts passed/failed/skipped statuses', () => {
    for (const status of ['passed', 'failed', 'skipped'] as const) {
      const result = ToolResultSchema.safeParse({ ...BASE_TOOL_RESULT, status });
      expect(result.success).toBe(true);
    }
  });

  it('rejects unknown statuses and negative durations', () => {
    expect(
      ToolResultSchema.safeParse({ ...BASE_TOOL_RESULT, status: 'completed' }).success,
    ).toBe(false);
    expect(
      ToolResultSchema.safeParse({ ...BASE_TOOL_RESULT, durationMs: -1 }).success,
    ).toBe(false);
  });
});

describe('NormalizedFindingSchema', () => {
  it('accepts the valid finding fixture', () => {
    expect(NormalizedFindingSchema.safeParse(findingValid).success).toBe(true);
  });

  it('rejects the invalid finding fixture (bad fingerprint, category, severity)', () => {
    const result = NormalizedFindingSchema.safeParse(findingInvalid);
    expect(result.success).toBe(false);
  });

  it('requires a 16-char lowercase hex fingerprint', () => {
    for (const fingerprint of ['ABCDEF0123456789', 'short', 'xyz123xyz123xyz1']) {
      expect(
        NormalizedFindingSchema.safeParse({ ...findingValid, fingerprint }).success,
      ).toBe(false);
    }
  });
});

describe('SecurityScoreSchema', () => {
  it('accepts the valid score fixture', () => {
    expect(SecurityScoreSchema.safeParse(scoreValid).success).toBe(true);
  });

  it('rejects out-of-range scores and unknown versions', () => {
    expect(
      SecurityScoreSchema.safeParse({ ...scoreValid, overall: 101 }).success,
    ).toBe(false);
    expect(
      SecurityScoreSchema.safeParse({ ...scoreValid, scoringVersion: 'v2.0' }).success,
    ).toBe(false);
  });
});

describe('ScanEventSchema', () => {
  it('accepts the valid event fixture', () => {
    expect(ScanEventSchema.safeParse(eventValid).success).toBe(true);
  });

  it('rejects non-datetime timestamps', () => {
    expect(
      ScanEventSchema.safeParse({ ...eventValid, timestamp: 'not-a-date' }).success,
    ).toBe(false);
  });
});
