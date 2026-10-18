import { randomBytes } from "node:crypto";
import { apiStore } from "./store";

const COOKIE = "shipsafe_workspace";
const globalState = globalThis as typeof globalThis & { shipSafeWorkspaces?: Set<string> };
const workspaces = globalState.shipSafeWorkspaces ??= new Set<string>();

/** A browser capability, not an email identity or an authenticated team account. */
export function workspaceId(request: Request): string | undefined {
  const value = request.headers.get("cookie")?.split(";")
    .map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);
  if (!value || !/^[a-f0-9]{64}$/.test(value)) return undefined;
  // In production the cookie is a bearer capability whose ownership is checked
  // by every project and scan query in the persistent runtime store.
  if (process.env.VERCEL) return process.env.DATABASE_URL ? value : undefined;
  return workspaces.has(value) || apiStore.hasOwner(value) ? value : undefined;
}

export function ensureWorkspace(request: Request): { id: string; cookie?: string } {
  const existing = workspaceId(request);
  if (existing) return { id: existing };
  const id = randomBytes(32).toString("hex");
  workspaces.add(id);
  const proto = request.headers.get("x-forwarded-proto") || new URL(request.url).protocol.replace(":", "");
  return {
    id,
    cookie: `${COOKIE}=${id}; Path=/; HttpOnly; SameSite=Strict${proto === "https" ? "; Secure" : ""}`,
  };
}

export function json(body: unknown, status = 200, cookie?: string): Response {
  const headers = new Headers({ "Cache-Control": "no-store", "Vary": "Cookie" });
  if (cookie) headers.set("Set-Cookie", cookie);
  return Response.json(body, { status, headers });
}

/** A stable public response for storage or durable-dispatch failures. */
export function serviceUnavailable(code: "STORAGE_UNAVAILABLE" | "DISPATCH_UNAVAILABLE" = "STORAGE_UNAVAILABLE", cookie?: string): Response {
  return json({ error: code === "DISPATCH_UNAVAILABLE" ? "Durable scan dispatch is unavailable." : "Persistent scan storage is unavailable.", code }, 503, cookie);
}

/** Reject browser mutations originating outside this application. */
export function mutationAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return request.headers.get("sec-fetch-site") !== "cross-site";
  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    const isLocal = (h: string) => h === "localhost" || h === "127.0.0.1";
    const sameOrigin = originUrl.origin === requestUrl.origin ||
      (originUrl.protocol === requestUrl.protocol &&
       originUrl.port === requestUrl.port &&
       isLocal(originUrl.hostname) &&
       isLocal(requestUrl.hostname));
    return Boolean(sameOrigin && request.headers.get("sec-fetch-site") !== "cross-site");
  } catch {
    return false;
  }
}
