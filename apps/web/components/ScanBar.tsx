"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { z } from "zod";

const urlSchema = z
  .string()
  .trim()
  .min(1, "Enter a URL to scan.")
  .refine(
    (v) => {
      try {
        const u = new URL(v.startsWith("http") ? v : `https://${v}`);
        return u.protocol === "http:" || u.protocol === "https:";
      } catch {
        return false;
      }
    },
    { message: "Enter a valid http(s) URL, e.g. https://example.com" },
  );

const PRESETS = ["https://example.com", "https://httpbin.org"];

interface ScanCreateResponse {
  id?: string;
  scan_id?: string;
}

/** URL input + Scan button. POSTs /api/scans, routes to /scan/[id]; falls back to the offline demo on failure. */
export default function ScanBar({ compact = false }: { compact?: boolean }) {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(target: string) {
    const parsed = urlSchema.safeParse(target);
    if (!parsed.success) {
      setError(parsed.error.issues[0]?.message ?? "Invalid URL.");
      return;
    }
    setError(null);
    setBusy(true);
    let value = parsed.data;
    if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target: value }),
      });
      if (!res.ok) throw new Error(`scan request failed (${res.status})`);
      const data = (await res.json()) as ScanCreateResponse;
      const id = data.id ?? data.scan_id;
      if (!id) throw new Error("scan request returned no id");
      router.push(`/scan/${id}`);
    } catch {
      // API offline or route not implemented yet: show the sample report.
      router.push("/scan/demo");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      {!compact && (
        <form
          className="ss-scanbar"
          onSubmit={(e) => {
            e.preventDefault();
            void submit(url);
          }}
        >
          <input
            className="ss-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="https://yourapp.com"
            aria-label="Target URL to scan"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={busy}
          />
          <button className="ss-btn ss-btn-primary" type="submit" disabled={busy}>
            {busy ? "Starting scan…" : "Scan your app"}
          </button>
        </form>
      )}
      <div className="ss-presets">
        <span>Quick test:</span>
        {PRESETS.map((p) => (
          <button
            key={p}
            type="button"
            className="ss-preset"
            disabled={busy}
            onClick={() => {
              setUrl(p);
              void submit(p);
            }}
          >
            {p}
          </button>
        ))}
      </div>
      {error && (
        <p className="ss-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
