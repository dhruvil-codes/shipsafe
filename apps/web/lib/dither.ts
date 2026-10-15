/**
 * Ordered-dither field for the landing background.
 * Pure math (no DOM) so the field is unit-testable; the canvas component in
 * `DitherBackground.tsx` only samples it.
 *
 * The field is a blueprint-style dot grid: a Bayer-4 ordered threshold gives
 * the print-like grain, a slow time drift keeps it alive, and the pointer
 * position opens a "lens" where dots swell. All values are 0..1 intensities
 * in the page ink — never colour, never glow.
 */

const BAYER_4 = [
  [0, 8, 2, 10],
  [12, 4, 14, 6],
  [3, 11, 1, 9],
  [15, 7, 13, 5],
];

/** Ordered threshold in [0, 1) for cell (col, row). */
export function bayerThreshold(col: number, row: number): number {
  const r = BAYER_4[((row % 4) + 4) % 4] as number[];
  const v = r[((col % 4) + 4) % 4] as number;
  return (v + 0.5) / 16;
}

export interface DitherSample {
  /** Dot radius multiplier, 0 (no dot) .. 1 (full cell). */
  intensity: number;
}

/**
 * Sample the field for one grid cell.
 * @param col,row cell indices; @param t seconds since mount (drift);
 * @param px,py pointer position in the same units as cx,cy (use -1 when off-canvas);
 * @param cx,cy cell centre in pixels; @param cell grid pitch in pixels.
 */
export function sampleDither(
  col: number,
  row: number,
  t: number,
  px: number,
  py: number,
  cx: number,
  cy: number,
  cell: number,
): DitherSample {
  const base = 0.16 + 0.1 * Math.sin(t * 0.6 + (col + row) * 0.35);
  let glow = 0;
  if (px >= 0 && py >= 0) {
    const dx = cx - px;
    const dy = cy - py;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const radius = cell * 9;
    if (dist < radius) {
      const fall = 1 - dist / radius;
      glow = fall * fall * 0.75;
    }
  }
  const level = base + glow;
  const on = level > bayerThreshold(col, row) ? 1 : 0;
  if (!on) return { intensity: 0 };
  // Radius grows with overshoot so the lens edge feels continuous.
  const overshoot = Math.min(1, (level - 0.16) / 0.75);
  return { intensity: 0.35 + 0.65 * overshoot };
}
