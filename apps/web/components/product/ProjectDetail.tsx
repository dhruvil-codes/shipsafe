"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell, Badge, ButtonLink, EmptyState, ErrorNotice, PageHeading } from "@/components/product-ui";
import { Verification } from "@/components/product/Verification";
import { ScanTable } from "@/components/product/ScanTable";
import { dateLabel, isVerified, useResource, type Project, type ScanRecord } from "@/components/product/data";

export function ProjectDetail({ id }: { id: string }) {
  const { data, error, loading, retry } = useResource<{ project: Project; scans: ScanRecord[] }>(`/api/projects/${encodeURIComponent(id)}`);
  const [project, setProject] = useState<Project | null>(null);
  useEffect(() => { if (data) setProject(data.project); }, [data]);
  return <AppShell><div className="page-container stack"><Link href="/projects" className="small muted">← Projects</Link>
    {loading ? <div className="panel" role="status">Loading project…</div> : error ? <><PageHeading eyebrow="Project overview" title="Project unavailable" description="The project could not be retrieved. Retry or return to your project list." /><ErrorNotice message={error} retry={retry} /></> : project && <>
      <PageHeading eyebrow="Project overview" title={project.name} description={project.url} action={isVerified(project) ? <ButtonLink href={`/projects/${project.id}/scan`}>New baseline scan →</ButtonLink> : undefined} />
      <div className="row"><Badge>{project.environment}</Badge><Badge tone={isVerified(project) ? "success" : "warning"}>{isVerified(project) ? "Domain verified" : "Verification needed"}</Badge><span className="small muted">Created {dateLabel(project.createdAt)}</span></div>
      {!isVerified(project) && <Verification project={project} onVerified={setProject} />}
      <section className="stack"><div><h2 className="section-title">Assessment history</h2><p className="muted small">Every run recorded for this project, with the coverage it actually achieved.</p></div>
        {data?.scans.length ? <div className="panel"><ScanTable scans={data.scans} /></div> : <EmptyState title="A clean slate." description="No scans have run for this project. Verify the domain, then configure your first baseline assessment." action={isVerified(project) ? <ButtonLink href={`/projects/${project.id}/scan`}>Configure baseline →</ButtonLink> : undefined} />}
      </section>
    </>}
  </div></AppShell>;
}

