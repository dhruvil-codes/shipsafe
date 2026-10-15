"use client";

import { useEffect, useRef } from "react";

function lineClass(line: string): string {
  if (/^\$ /.test(line)) return "ss-term-line ss-term-cmd";
  if (/\[stderr\]|ERROR|FAIL|WARN/i.test(line)) {
    return /\[stderr\]|ERROR|FAIL/i.test(line)
      ? "ss-term-line ss-term-err"
      : "ss-term-line";
  }
  if (/^\[(done|tls|files|ports)\].*OK|complete/i.test(line))
    return "ss-term-line ss-term-ok";
  return "ss-term-line";
}

interface TerminalProps {
  lines: string[];
  title?: string;
}

/** Terminal window streaming scan-runner output with auto-scroll. */
export default function Terminal({ lines, title = "shipsafe-runner" }: TerminalProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div className="ss-terminal">
      <div className="ss-panel-head">
        <span>{title} — live log</span>
        <span className="ss-terminal-dots" aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
      </div>
      <div
        className="ss-terminal-scroll"
        ref={scrollRef}
        role="log"
        aria-label="Scan execution log"
      >
        {lines.map((line, i) => (
          <p key={i} className={lineClass(line)}>
            {line}
          </p>
        ))}
        <span className="ss-term-cursor" aria-hidden="true" />
      </div>
    </div>
  );
}
