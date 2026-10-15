"use client";

import { useState } from "react";
import { buildAiFixPrompt, type UiFinding } from "../lib/scan-flow";

interface AIFixPromptCardProps {
  target: string;
  score: number | null;
  findings: UiFinding[];
}

/** Hero feature: ready-to-paste remediation prompt for AI coding assistants. */
export default function AIFixPromptCard({ target, score, findings }: AIFixPromptCardProps) {
  const [copied, setCopied] = useState(false);
  const prompt = buildAiFixPrompt(target, score, findings);

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="term-ai" aria-label="AI fix prompt">
      <div className="term-ai-head">
        <span aria-hidden="true">🤖</span>
        <h3>1-CLICK AI FIX PROMPT</h3>
        <span className="term-ai-sub">Copy into Cursor / Claude Code / ChatGPT</span>
      </div>
      <pre className="term-ai-body">{prompt}</pre>
      <button type="button" className="term-ai-copy" onClick={() => void copyPrompt()}>
        {copied ? "Copied! ✓" : "📋 COPY AI PROMPT"}
      </button>
    </section>
  );
}
