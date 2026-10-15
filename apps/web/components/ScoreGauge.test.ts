import { describe, expect, it } from "vitest";
import { gradeForScore } from "./ScoreGauge";

describe("gradeForScore", () => {
  it("awards A at 90 and above", () => {
    expect(gradeForScore(100)).toBe("A");
    expect(gradeForScore(90)).toBe("A");
  });

  it("awards B from 70 to 89", () => {
    expect(gradeForScore(89)).toBe("B");
    expect(gradeForScore(70)).toBe("B");
  });

  it("awards C from 50 to 69", () => {
    expect(gradeForScore(69)).toBe("C");
    expect(gradeForScore(50)).toBe("C");
  });

  it("awards F below 50", () => {
    expect(gradeForScore(49)).toBe("F");
    expect(gradeForScore(0)).toBe("F");
  });
});
