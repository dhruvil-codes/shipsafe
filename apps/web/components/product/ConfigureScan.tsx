"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppShell, Badge, ButtonLink, ErrorNotice, PageHeading } from "@/components/product-ui";
import { isVerified, request, useResource, type Project, type Workspace } from "@/components/product/data";

export function ConfigureScan({ id }: { id: string }) {
  const router = useRouter();
  const projectState = useResource<{ project: Project }>(`/api/projects/${encodeURIComponent(id)}`);
  const workspaceState = useResource<Workspace>("/api/workspace");
  const [accepted, setAccepted] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const project = projectState.data?.project;
  const workspace = workspaceState.data;
  const verified = project ? isVerified(project) : false;
  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!accepted || !verified || !workspace?.executionConfigured || starting) return;
    setStarting(true); setError("");
    try {
      const result = await request<{ scanId: string }>("/api/scans", { method: "POST", body: JSON.stringify({ projectId: id, scopeAccepted: true }) });
      router.push(`/scan/${result.scanId}`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not start scan."); setStarting(false); }
  }
  return <AppShell><div className="page-container stack">
    <Link href={`/projects/${id}`} className="small muted">← Project overview</Link>
    <PageHeading eyebrow="New assessment" title="Know your baseline." description="Review what will run, confirm the target, and authorize the scope." />
    {projectState.loading || workspaceState.loading ? <div className="panel" role="status">Checking project and scan readiness…</div> : projectState.error ? <ErrorNotice message={projectState.error} retry={projectState.retry} /> : workspaceState.error ? <ErrorNotice message={workspaceState.error} retry={workspaceState.retry} /> : project && <form onSubmit={start} className="stack">
      <div className="split"><section className="panel stack"><Badge tone="info">Selected profile</Badge><div><h2 className="section-title">Baseline assessment</h2><p className="muted">Non-invasive HTTP, TLS, security header, and passive checks against your verified website.</p></div><div><h3 className="small">Included</h3><ul className="muted"><li>Transport and TLS configuration</li><li>HTTP security headers</li><li>Passive observations from the approved target</li></ul></div><p className="small muted">Requires current domain verification. No login sessions, repository analysis, exploitation, or active application testing. Duration depends on target availability and enabled tools.</p></section>
      <aside className="panel stack"><Badge>Future integration</Badge><div><h2 className="section-title">Code audit</h2><p className="muted">Repository, dependency, and secret analysis needs a connected source integration.</p></div><p className="small muted">GitHub connection is not available in this workspace. Code audit cannot be selected or started.</p></aside></div>
      <section className="panel stack"><div><h2 className="section-title">Target & authorization</h2><p className="muted">{project.name}</p><p style={{ overflowWrap: "anywhere" }}>{project.url}</p></div><Badge tone={verified ? "success" : "warning"}>{verified ? "Current ownership verified" : "Current ownership verification required"}</Badge>
      {!verified && <div className="notice"><p>Verify domain ownership before starting a scan.</p><ButtonLink href={`/projects/${id}` } secondary>Verify domain →</ButtonLink></div>}
      <label className="row" style={{ alignItems: "flex-start" }}><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} required disabled={!verified} style={{ width: 20, height: 20, flexShrink: 0, marginTop: 3 }} /><span>I own or am authorized to test this website and authorize the baseline assessment of the exact target shown above. <span className="muted">This does not authorize testing third-party domains or active exploitation.</span></span></label></section>
      {!workspace?.executionConfigured && <section className="notice stack"><div><h2 className="section-title">Scan execution is not ready.</h2><p className="muted">Your project can be saved and verified. Starting scans stays unavailable until the backend meets the required execution safeguards.</p></div>{workspace?.executionBlockers?.length ? <ul>{workspace.executionBlockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul> : null}<div className="row"><ButtonLink href="/settings" secondary>View setup details →</ButtonLink><Link href="/report/sample">Explore the sample report →</Link></div></section>}
      {error && <ErrorNotice message={error} />}
      <div className="row"><button className="button" type="submit" disabled={!accepted || !verified || !workspace?.executionConfigured || starting}>{starting ? "Starting assessment…" : "Start baseline assessment →"}</button><span className="small muted">Only completed checks contribute to your report.</span></div>
    </form>}
  </div></AppShell>;
}

