"use client";

import { useState, useCallback, type FormEvent } from "react";
import { Shield, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

interface ScanInputProps {
  scanning: boolean;
  onSubmit: (url: string) => void;
}

/**
 * Single-line URL input — the only thing on the hero.
 * Prepends https:// if no protocol is present.
 */
export default function ScanInput({ scanning, onSubmit }: ScanInputProps) {
  const [value, setValue] = useState("");

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      const raw = value.trim();
      if (!raw) return;
      const url = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
      onSubmit(url);
    },
    [value, onSubmit],
  );

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-xl mx-auto">
      <div className="relative flex items-center gap-3 p-1.5 rounded-xl border border-(--color-border) bg-(--color-bg-card) shadow-[0_0_40px_rgba(99,102,241,0.08)] transition-all duration-300 focus-within:border-(--color-accent)/40 focus-within:shadow-[0_0_60px_rgba(99,102,241,0.15)]">
        <div className="flex items-center gap-2 pl-3">
          <Shield className="w-4 h-4 text-(--color-text-muted)" />
          <span className="text-xs text-(--color-text-muted) font-mono hidden sm:inline">https://</span>
        </div>
        <Input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="yourwebsite.com"
          disabled={scanning}
          className="border-0 bg-transparent h-10 focus:ring-0 focus:outline-none px-0 text-sm"
          aria-label="Website URL to scan"
          autoComplete="url"
        />
        <Button
          type="submit"
          disabled={scanning || !value.trim()}
          size="default"
          className="shrink-0 rounded-lg"
        >
          {scanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="hidden sm:inline">Scanning...</span>
            </>
          ) : (
            <>
              <span>Scan</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </Button>
      </div>
      <p className="text-center text-[11px] text-(--color-text-muted) mt-3 tracking-wide">
        Runs real scanners on an isolated micro-VM. No simulation, no guesses.
      </p>
    </form>
  );
}
