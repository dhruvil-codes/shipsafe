"use client";

/**
 * Isometric grid of cubes that represents the security scanning infrastructure.
 * Pure SVG — no external assets needed.
 */
export default function IsometricGrid() {
  // Isometric transformation helpers
  const isoX = (col: number, row: number) => 200 + (col - row) * 40;
  const isoY = (col: number, row: number) => 60 + (col + row) * 24;

  const cubes = [
    // Main cluster
    { col: 0, row: 0, h: 60, fill: "#6366f1", opacity: 0.9, delay: 0 },
    { col: 1, row: 0, h: 40, fill: "#818cf8", opacity: 0.7, delay: 0.1 },
    { col: 2, row: 0, h: 30, fill: "#6366f1", opacity: 0.5, delay: 0.2 },
    { col: 0, row: 1, h: 45, fill: "#818cf8", opacity: 0.8, delay: 0.15 },
    { col: 1, row: 1, h: 70, fill: "#4f46e5", opacity: 1, delay: 0.05 },
    { col: 2, row: 1, h: 35, fill: "#6366f1", opacity: 0.6, delay: 0.25 },
    { col: 0, row: 2, h: 25, fill: "#6366f1", opacity: 0.4, delay: 0.3 },
    { col: 1, row: 2, h: 50, fill: "#818cf8", opacity: 0.7, delay: 0.2 },
    { col: 2, row: 2, h: 55, fill: "#4f46e5", opacity: 0.85, delay: 0.1 },
    // Floating accent cubes
    { col: 3, row: 1, h: 20, fill: "#22c55e", opacity: 0.6, delay: 0.4 },
    { col: 1, row: 3, h: 15, fill: "#06b6d4", opacity: 0.5, delay: 0.45 },
  ];

  return (
    <div className="relative w-full max-w-[400px] mx-auto" aria-hidden="true">
      <svg viewBox="0 0 400 280" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-auto">
        {/* Ambient glow */}
        <defs>
          <radialGradient id="glow" cx="50%" cy="40%" r="50%">
            <stop offset="0%" stopColor="#6366f1" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0" />
          </radialGradient>
          <filter id="shadow">
            <feDropShadow dx="0" dy="4" stdDeviation="6" floodColor="#000" floodOpacity="0.3" />
          </filter>
        </defs>
        <rect width="400" height="280" fill="url(#glow)" />

        {cubes.map((cube, i) => {
          const x = isoX(cube.col, cube.row);
          const y = isoY(cube.col, cube.row);
          const h = cube.h;

          // Isometric cube faces
          const topPoints = `${x},${y - h} ${x + 40},${y - h + 24} ${x},${y - h + 48} ${x - 40},${y - h + 24}`;
          const leftPoints = `${x - 40},${y - h + 24} ${x},${y - h + 48} ${x},${y + 48} ${x - 40},${y + 24}`;
          const rightPoints = `${x},${y - h + 48} ${x + 40},${y - h + 24} ${x + 40},${y + 24} ${x},${y + 48}`;

          return (
            <g
              key={i}
              opacity={cube.opacity}
              filter="url(#shadow)"
              style={{
                animation: `fade-in 0.6s ease-out ${cube.delay}s both`,
              }}
            >
              {/* Left face (darker) */}
              <polygon
                points={leftPoints}
                fill={cube.fill}
                opacity={0.6}
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="0.5"
              />
              {/* Right face (medium) */}
              <polygon
                points={rightPoints}
                fill={cube.fill}
                opacity={0.4}
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="0.5"
              />
              {/* Top face (lightest) */}
              <polygon
                points={topPoints}
                fill={cube.fill}
                opacity={0.85}
                stroke="rgba(255,255,255,0.1)"
                strokeWidth="0.5"
              />
            </g>
          );
        })}

        {/* Scan beam effect on the tallest cube */}
        <rect
          x={isoX(1, 1) - 20}
          y={isoY(1, 1) - 70}
          width="40"
          height="2"
          fill="#22c55e"
          opacity="0.8"
          rx="1"
          style={{ animation: "scan-line 3s linear infinite" }}
        />
      </svg>
    </div>
  );
}
