"use client";

import { useState } from "react";
import { normalizeUrlInput } from "../lib/scan-flow";

const PRESETS = ["example.com", "httpbin.org", "testphp.vulnweb.com"];

interface CommandBarProps {
  scanning: boolean;
  onSubmit: (url: string) => void;
}

/** `$ shipsafe scan [url]` prompt with run button + demo chips. */
export default function CommandBar({ scanning, onSubmit }: CommandBarProps) {
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
    <div className="term-cmd">
      <form
        className="term-cmd-row"
        onSubmit={(e) => {
          e.preventDefault();
          submit(value);
        }}
      >
        <span className="term-prompt" aria-hidden="true">
          $
        </span>
        <span className="term-cmd-text" aria-hidden="true">
          shipsafe scan&nbsp;
        </span>
        <input
          className="term-input"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="[ https://your-domain.com ]"
          aria-label="Target URL to scan"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={scanning}
        />
        <button
          type="submit"
          className="term-run"
          disabled={scanning}
        >
          {scanning ? "SCANNING…" : "⚡ RUN SECURITY SCAN"}
        </button>
      </form>
      <div className="term-chips">
        <span className="term-chips-label">quick demo:</span>
        {PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className="term-chip"
            disabled={scanning}
            onClick={() => {
              setValue(`https://${p}`);
              submit(p);
            }}
          >
            [ {p} ]
          </button>
        ))}
      </div>
      {error && (
        <p className="term-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
