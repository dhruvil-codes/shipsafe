"use client";

import { useCallback, useEffect, useState } from "react";

export type DeepScanClass = "configuration" | "discovery" | "cors" | "vulnerability";

export interface SecurityAuthorization {
  id: string;
  hostname: string;
  classes: DeepScanClass[];
  createdAt: string;
  expiresAt: string;
  revokedAt?: string | null;
}

export interface Project {
  id: string;
  name: string;
  url: string;
  environment: "production" | "staging" | "development";
  securityAuthorization?: SecurityAuthorization;
  verificationToken: string;
  verifiedAt: string | null;
  verificationExpiresAt: string | null;
  createdAt: string;
}

export interface ScanRecord {
  id: string;
  projectId: string;
  projectName?: string;
  url: string;
  mode?: "website" | "lab" | "standard" | "deep";
  authorizationId?: string;
  status: string;
  score?: number;
  coverage?: number;
  createdAt: string;
}

export interface Workspace {
  mode: "browser";
  persistence: "local-file" | "memory";
  executionConfigured: boolean;
  labEnabled: boolean;
  githubConfigured: boolean;
  executionBlockers?: string[];
}

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof body.error === "string" ? body.error : body.error?.message ?? body.message;
    const details = Array.isArray(body.details) ? body.details.filter((detail: unknown) => typeof detail === "string").join(" ") : "";
    throw new Error([message, details].filter(Boolean).join(". ") || `Request failed (${response.status}). Please try again.`);
  }
  return body as T;
}

let workspaceInitialization: Promise<Workspace> | null = null;

/** Coalesce concurrent cookie initialization before any workspace data request. */
function initializeWorkspace(): Promise<Workspace> {
  if (!workspaceInitialization) {
    workspaceInitialization = fetchJson<Workspace>("/api/workspace")
      .finally(() => { workspaceInitialization = null; });
  }
  return workspaceInitialization;
}

/** Same-origin browser requests retain a consistently initialized workspace cookie. */
export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const workspace = await initializeWorkspace();
  if (path === "/api/workspace" && (!options?.method || options.method === "GET")) return workspace as T;
  return fetchJson<T>(path, options);
}

/** Fetch on entry and expose explicit retry without fabricating fallback data. */
export function useResource<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const retry = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");
    request<T>(path).then((value) => { if (active) setData(value); })
      .catch((reason: Error) => { if (active) setError(reason.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [path, revision]);
  return { data, error, loading, retry };
}

export function isVerified(project: Project): boolean {
  return Boolean(project.verifiedAt && project.verificationExpiresAt && Date.parse(project.verificationExpiresAt) > Date.now());
}

export function dateLabel(value: string): string {
  return new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
