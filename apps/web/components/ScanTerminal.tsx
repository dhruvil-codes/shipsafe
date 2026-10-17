"use client";

import { useEffect, useRef } from "react";
import { Terminal as TerminalIcon } from "lucide-react";

interface ScanTerminalProps {
  lines: string[];
  sandboxId: string;
  vmLabel: string;
}

/**
 * Terminal-style console showing real-time scan output.
 * Auto-scrolls as new lines arrive.
 */
export default function ScanTerminal({ lines, sandboxId, vmLabel }: ScanTerminalProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines.length]);

  return (
    <div className="terminal-container animate-fade-in">
      <div className="terminal-header">
        <div className="flex items-center gap-3">
          <div className="terminal-dots">
            <span />
            <span />
            <span />
          </div>
          <span className="text-[11px] text-(--color-text-muted) font-mono">
            shipsafe — scan
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-(--color-text-muted) font-mono">
            {sandboxId}
          </span>
          <span className="flex items-center gap-1.5 text-[10px] font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-(--color-green) animate-pulse" />
            <span className="text-(--color-green)">{vmLabel}</span>
          </span>
        </div>
      </div>
      <div className="terminal-body">
        {lines.length === 0 ? (
          <div className="flex items-center gap-2 text-(--color-text-muted)">
            <TerminalIcon className="w-3.5 h-3.5" />
            <span>Waiting for VM output...</span>
          </div>
        ) : (
          lines.map((line, i) => (
            <div key={i} className="flex gap-2 hover:bg-white/[0.02] px-1 -mx-1 rounded">
              <span className="text-(--color-text-muted) select-none w-8 text-right shrink-0 tabular-nums">
                {i + 1}
              </span>
              <span
                className={
                  line.startsWith("[ERROR]") || line.startsWith("[error]")
                    ? "text-(--color-red)"
                    : line.startsWith("[cancel]")
                      ? "text-(--color-amber)"
                      : line.startsWith("$")
                        ? "text-(--color-green)"
                        : ""
                }
              >
                {line}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
