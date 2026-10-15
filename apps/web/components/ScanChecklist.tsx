"use client";

import type { EngineCheck } from "../lib/scan-flow";

const STATE_GLYPH: Record<EngineCheck["state"], string> = {
  pending: "○",
  running: "◌",
  passed: "✓",
  warning: "!",
};

/** Right-panel live checklist for the five reconnaissance engines. */
export default function ScanChecklist({ items }: { items: EngineCheck[] }) {
  return (
    <ul className="term-checks" aria-live="polite" aria-label="Engine checklist">
      {items.map((item) => (
        <li key={item.id} className={`term-check term-check-${item.state}`}>
          <span className="term-check-glyph" aria-hidden="true">
            {STATE_GLYPH[item.state]}
          </span>
          <div className="term-check-text">
            <p className="term-check-label">{item.label}</p>
            <p className="term-check-detail">{item.detail}</p>
          </div>
          <span className={`term-check-pill term-pill-${item.state}`}>
            {item.state.toUpperCase()}
          </span>
        </li>
      ))}
    </ul>
  );
}
