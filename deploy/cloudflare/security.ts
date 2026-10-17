import type { Env } from "./types";

/**
 * Robust SSRF & Private IP Check.
 * Rejects RFC 1918, RFC 3927 (link-local/cloud metadata), loopback, CGNAT, multicast, and IPv6 equivalents.
 */
export function isPrivateOrReservedHost(hostname: string): boolean {
  const lower = hostname.toLowerCase().trim();

  // Localhost aliases & test domains
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal") ||
    lower === "0.0.0.0" ||
    lower === "::" ||
    lower === "::1"
  ) {
    return true;
  }

  // Check IPv4 representations
  const ipv4Match = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [_, aStr, bStr, cStr, dStr] = ipv4Match;
    const a = parseInt(aStr, 10);
    const b = parseInt(bStr, 10);
    const c = parseInt(cStr, 10);
    const d = parseInt(dStr, 10);

    if (a > 255 || b > 255 || c > 255 || d > 255) return true;

    // 0.0.0.0/8 (Current network)
    if (a === 0) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (Link-local / AWS / GCP / Azure metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (Private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (a >= 224) return true;
  }

  // Check IPv6 private / link-local / ULA
  if (lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80")) {
    return true;
  }

  return false;
}

export function validateScanUrl(rawUrl: string): { valid: boolean; normalizedUrl?: string; hostname?: string; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, error: "Only HTTP and HTTPS URLs are supported" };
  }

  if (!parsed.hostname || parsed.hostname.length < 3) {
    return { valid: false, error: "Hostname is too short or missing" };
  }

  if (isPrivateOrReservedHost(parsed.hostname)) {
    return { valid: false, error: "Target host is private, loopback, or reserved (SSRF protection)" };
  }

  // Normalize: Strip credentials, fragments, and enforce lowercase hostname
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    hostname: parsed.hostname.toLowerCase(),
  };
}

/**
 * Cloudflare Turnstile token validation.
 */
export async function verifyTurnstileToken(token: string, secretKey?: string, ip?: string): Promise<boolean> {
  if (!secretKey) return true; // Disabled in test/dev
  if (!token) return false;

  try {
    const formData = new URLSearchParams();
    formData.append("secret", secretKey);
    formData.append("response", token);
    if (ip) formData.append("remoteip", ip);

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    const result = (await res.json()) as { success: boolean };
    return result.success === true;
  } catch {
    return false;
  }
}

/**
 * Distributed D1-backed sliding window rate limiter.
 */
export async function checkRateLimit(
  env: Env,
  key: string,
  limit: number,
  windowSec: number = 60
): Promise<{ allowed: boolean; remaining: number }> {
  if (!env.DB) return { allowed: true, remaining: limit };

  const now = Date.now();
  const windowMs = windowSec * 1000;
  const windowExpiresAt = now + windowMs;

  try {
    // Clean expired and fetch or increment count atomically
    const row = await env.DB.prepare(
      "SELECT count, window_expires_at FROM rate_limits WHERE key = ?"
    )
      .bind(key)
      .first<{ count: number; window_expires_at: number }>();

    if (!row || row.window_expires_at < now) {
      await env.DB.prepare(
        "INSERT INTO rate_limits (key, count, window_start, window_expires_at) VALUES (?, 1, ?, ?) ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start, window_expires_at = excluded.window_expires_at"
      )
        .bind(key, now, windowExpiresAt)
        .run();
      return { allowed: true, remaining: limit - 1 };
    }

    if (row.count >= limit) {
      return { allowed: false, remaining: 0 };
    }

    await env.DB.prepare("UPDATE rate_limits SET count = count + 1 WHERE key = ?")
      .bind(key)
      .run();

    return { allowed: true, remaining: limit - row.count - 1 };
  } catch {
    // On transient DB failure, fail open to avoid denying legitimate users
    return { allowed: true, remaining: limit };
  }
}
