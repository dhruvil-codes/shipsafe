import { describe, expect, it } from "vitest";
import { bayerThreshold, sampleDither } from "./dither";

describe("bayerThreshold", () => {
  it("spans the full 0..1 range over one 4x4 tile", () => {
    const values = new Set<number>();
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) values.add(bayerThreshold(c, r));
    }
    expect(values.size).toBe(16);
    for (const v of values) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });

  it("tiles periodically and tolerates negatives", () => {
    expect(bayerThreshold(4, 0)).toBe(bayerThreshold(0, 0));
    expect(bayerThreshold(-1, -1)).toBe(bayerThreshold(3, 3));
  });
});

describe("sampleDither", () => {
  it("returns intensities in 0..1", () => {
    for (let i = 0; i < 64; i++) {
      const s = sampleDither(i, i * 3, i * 0.1, -1, -1, i * 10, i * 10, 14);
      expect(s.intensity).toBeGreaterThanOrEqual(0);
      expect(s.intensity).toBeLessThanOrEqual(1);
    }
  });

  it("brightens cells near the pointer", () => {
    const near = sampleDither(8, 8, 0, 112, 112, 112, 112, 14);
    const far = sampleDither(8, 8, 0, 4000, 4000, 112, 112, 14);
    expect(near.intensity).toBeGreaterThanOrEqual(far.intensity);
  });
});
