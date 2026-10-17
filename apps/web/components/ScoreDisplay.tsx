"use client";

interface ScoreDisplayProps {
  score: number | null;
  coverage: number | null;
  capped: boolean;
}

/**
 * Circular score gauge with coverage indicator.
 */
export default function ScoreDisplay({ score, coverage, capped }: ScoreDisplayProps) {
  if (score === null) return null;

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progress = ((score ?? 0) / 100) * circumference;
  const scoreColor =
    score >= 80 ? "var(--color-green)" : score >= 50 ? "var(--color-amber)" : "var(--color-red)";

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          {/* Track */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="6"
          />
          {/* Progress */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke={scoreColor}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            style={{ transition: "stroke-dashoffset 1s ease-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-3xl font-bold tabular-nums"
            style={{ color: scoreColor }}
          >
            {score}
          </span>
          <span className="text-[10px] text-(--color-text-muted) uppercase tracking-wider">
            Score
          </span>
        </div>
      </div>
      <div className="space-y-2 text-sm">
        <div>
          <span className="text-(--color-text-muted) text-xs">Coverage</span>
          <p className="font-mono text-(--color-text-primary)">
            {coverage !== null ? `${coverage}%` : "—"}
          </p>
        </div>
        {capped && (
          <div className="text-[11px] text-(--color-red) flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-(--color-red)" />
            Score capped — critical findings present
          </div>
        )}
      </div>
    </div>
  );
}
