"use client";

import { useState } from "react";
import { Badge, ButtonLink, CopyButton, ErrorNotice } from "@/components/product-ui";
import { isVerified, request, type Project } from "./data";

/** DNS ownership must be verified by the server before configuration unlocks. */
export function Verification({ project, onVerified }: { project: Project; onVerified: (project: Project) => void }) {
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const hostname = new URL(project.url).hostname;
  async function verify() {
    setChecking(true); setError("");
    try {
      const result = await request<{ project: Project }>(`/api/projects/${project.id}/verify`, { method: "POST" });
      onVerified(result.project);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Verification failed. Please try again."); }
    finally { setChecking(false); }
  }
  if (isVerified(project)) return <section className="panel stack verification-panel"><Badge tone="success">Ownership verified</Badge><div><h2 className="section-title">You’re ready to configure a scan.</h2><p className="muted">The DNS record confirms ownership of {hostname}. You’ll authorize the scope before scanning.</p></div><div><ButtonLink href={`/projects/${project.id}/scan`}>Configure baseline →</ButtonLink></div></section>;
  return <section className="panel stack verification-panel">
    <div><Badge tone="warning">Ownership required</Badge><h2 className="section-title" style={{ marginTop: 16 }}>Verify your domain</h2><p className="muted">Add this TXT record with your DNS provider. ShipSafe checks the public record before allowing a scan.</p></div>
    <div className="form-field dns-field dns-type"><span className="small muted">Type</span><strong>TXT</strong></div>
    <div className="form-field dns-field"><span className="small muted">Record name / host</span><code className="dns-value">_shipsafe.{hostname}</code><div><CopyButton text={`_shipsafe.${hostname}`} label="Copy record name" /></div></div>
    <div className="form-field dns-field"><span className="small muted">Record value</span><code className="dns-value">shipsafe-verification={project.verificationToken}</code><div><CopyButton text={`shipsafe-verification=${project.verificationToken}`} label="Copy record value" /></div></div>
    <p className="muted small">Some providers append your domain automatically; enter only <code>_shipsafe</code> in that case. DNS updates can take time to appear. Keep this record in place for future checks.</p>
    {error && <ErrorNotice message={error} />}
    <div><button className="button" disabled={checking} onClick={verify}>{checking ? "Checking DNS…" : "Check verification →"}</button></div>
  </section>;
}
