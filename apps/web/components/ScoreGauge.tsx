export type Grade = "A" | "B" | "C" | "F";

/** Grade thresholds for the 0–100 assessed-security score. */
export function gradeForScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  return "F";
}

const RADIUS = 54;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface ScoreGaugeProps {
  score: number;
  coverage: number;
  capped?: boolean;
}

/** Circular radial SVG gauge: score 0–100, letter grade, coverage %. */
export default function ScoreGauge({ score, coverage, capped = false }: ScoreGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const offset = CIRCUMFERENCE - (clamped / 100) * CIRCUMFERENCE;
  const grade = gradeForScore(clamped);
  const stroke =
    grade === "A"
      ? "var(--ss-emerald)"
      : grade === "B"
        ? "var(--ss-sky)"
        : grade === "C"
          ? "var(--ss-amber)"
          : "var(--ss-rose)";

  return (
    <div className="ss-gauge-wrap">
      <svg
        className="ss-gauge-svg"
        viewBox="0 0 130 130"
        role="img"
        aria-label={`Security score ${clamped} out of 100, grade ${grade}`}
      >
        <circle cx="65" cy="65" r={RADIUS} fill="none" stroke="#1f1f23" strokeWidth="11" />
        <circle
          cx="65"
          cy="65"
          r={RADIUS}
          fill="none"
          stroke={stroke}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          transform="rotate(-90 65 65)"
        />
        <text
          x="65"
          y="62"
          textAnchor="middle"
          fill="var(--ss-text)"
          fontSize="30"
          fontWeight="750"
          fontFamily="Inter, sans-serif"
        >
          {clamped}
        </text>
        <text
          x="65"
          y="84"
          textAnchor="middle"
          fill="var(--ss-muted)"
          fontSize="12"
          fontFamily="'JetBrains Mono', monospace"
        >
          / 100
        </text>
      </svg>
      <p className="ss-gauge-grade">
        Grade {grade} · Assessed security
      </p>
      <p className="ss-gauge-coverage">Coverage {coverage}% of applicable controls</p>
      {capped && (
        <p className="ss-gauge-note">
          Capped at 40: an open critical finding overrides the aggregate score.
        </p>
      )}
      <p className="ss-gauge-note">
        Score is not a certification — see coverage and limitations.
      </p>
    </div>
  );
}
