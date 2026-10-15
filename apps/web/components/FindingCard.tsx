"use client";

import { useState } from "react";
import type { MockFinding } from "../lib/mock";

const SEVERITY_BADGE: Record<MockFinding["severity"], string> = {
  critical: "ss-badge-critical",
  high: "ss-badge-high",
  medium: "ss-badge-medium",
  low: "ss-badge-low",
  info: "ss-badge-info",
};

/** Expandable finding card: summary, severity badge, raw evidence, copy-fix button. */
export default function FindingCard({ finding }: { finding: MockFinding }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyFix() {
    try {
      await navigator.clipboard.writeText(
        `${finding.id} [${finding.severity.toUpperCase()}] ${finding.title}\n\nFix:\n${finding.fix}`,
      );
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <article className="ss-finding">
      <button
        className="ss-finding-head"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className={`ss-badge ${SEVERITY_BADGE[finding.severity]}`}>
          {finding.severity}
        </span>
        <span className="ss-finding-title">
          {finding.id} — {finding.title}
        </span>
        <span className="ss-finding-toggle" aria-hidden="true">
          {open ? "[-]" : "[+]"}
        </span>
      </button>
      {open && (
        <div className="ss-finding-body">
          <h4>What is wrong</h4>
          <p>{finding.summary}</p>
          <h4>Where</h4>
          <p>
            <code>{finding.affected}</code>
          </p>
          <h4>Evidence</h4>
          <pre className="ss-evidence">{finding.evidence}</pre>
          <h4>Recommended fix</h4>
          <p>{finding.fix}</p>
          <button
            type="button"
            className="ss-btn ss-btn-ghost ss-copy-btn"
            onClick={() => void copyFix()}
          >
            {copied ? "Copied to clipboard" : "Copy fix"}
          </button>
        </div>
      )}
    </article>
  );
}
