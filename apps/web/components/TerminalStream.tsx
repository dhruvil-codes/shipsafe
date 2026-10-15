"use client";

import { useEffect, useRef } from "react";

function streamLineClass(line: string): string {
  if (/^\$ /.test(line)) return "term-stream-line term-stream-cmd";
  if (/\[stderr\]|ERROR|FAIL|CRITICAL|VULN/i.test(line)) return "term-stream-line term-stream-err";
  if (/WARN|missing|misconfig|exposed|leak/i.test(line)) return "term-stream-line term-stream-warn";
  if (/\bOK\b|passed|complete|valid|secure|404|not found/i.test(line))
    return "term-stream-line term-stream-ok";
  return "term-stream-line";
}

/** Auto-scrolling console for live VM stdout. */
export default function TerminalStream({ lines }: { lines: string[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div
      className="term-stream"
      ref={scrollRef}
      role="log"
      aria-label="Live VM output"
    >
      {lines.length === 0 && (
        <p className="term-stream-line term-stream-dim">
          awaiting scan output — start a scan above.
        </p>
      )}
      {lines.map((line, i) => (
        <p key={i} className={streamLineClass(line)}>
          {line}
        </p>
      ))}
      <span className="term-cursor" aria-hidden="true" />
    </div>
  );
}
