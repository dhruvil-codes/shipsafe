"use client";

import { useState } from "react";
import { normalizeUrlInput } from "../lib/scan-flow";

const PRESETS = ["example.com", "httpbin.org", "testphp.vulnweb.com"];

interface ScanConsoleProps {
  scanning: boolean;
  onSubmit: (url: string) => void;
}

/**
 * The black command bar: URL input with a send action, preset chips below.
 * Mirrors the reference prompt bar; the send button runs a real micro-VM scan.
 */
export default function ScanConsole({ scanning, onSubmit }: ScanConsoleProps) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function submit(raw: string) {
    const parsed = normalizeUrlInput(raw);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    setError(null);
    onSubmit(parsed.url);
  }

  return (
    <div className="ds-console-wrap" id="scan">
      <form
        className="ds-console"
        onSubmit={(e) => {
          e.preventDefault();
          submit(value);
        }}
      >
        <span className="ds-console-glyph" aria-hidden="true">
          $
        </span>
        <input
          className="ds-console-input"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://your-domain.com"
          aria-label="Target URL to scan"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={scanning}
        />
        <button type="submit" className="ds-console-send" disabled={scanning} aria-label="Run security scan">
          {scanning ? (
            <span className="ds-console-spin" aria-hidden="true" />
          ) : (
            <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
              <path
                d="M2 9h11M9 3.5 14.5 9 9 14.5"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          )}
        </button>
      </form>
      <div className="ds-presets">
        {PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className="ds-chip"
            disabled={scanning}
            onClick={() => {
              setValue(`https://${p}`);
              submit(p);
            }}
          >
            {p} <span aria-hidden="true">›</span>
          </button>
        ))}
      </div>
      {error && (
        <p className="ds-form-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
