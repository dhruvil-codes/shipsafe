"use client";
import Link from "next/link";
import { ArrowUpRight, Check, Copy, Menu, X } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";

export function Logo() {
  return <Link href="/#scan" className="brand" aria-label="ShipSafe home"><ArrowUpRight size={23} strokeWidth={1.8} aria-hidden="true" /><span>ShipSafe</span></Link>;
}
export function ButtonLink({ href, children, secondary = false }: { href: string; children: ReactNode; secondary?: boolean }) {
  return <Link href={href} className={`button${secondary ? " secondary" : ""}`}>{children}</Link>;
}
export function OraNav() {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const links = <><Link href="/#scan-tree" onClick={() => setOpen(false)}>Scan tree</Link><Link href="/#scan" onClick={() => setOpen(false)}>Scan your app</Link></>;
  return <header className="ora-nav" onKeyDown={event => {
    if (event.key === "Escape" && open) { setOpen(false); trigger.current?.focus(); }
  }}><Logo /><nav className="ora-links" aria-label="Main navigation"><Link href="/#coverage">Coverage</Link><Link href="/#live">Baseline</Link><Link href="/#methodology">Methodology</Link>{links}</nav><button ref={trigger} className="icon-button mobile-menu" onClick={() => setOpen(!open)} aria-label={open ? "Close navigation" : "Open navigation"} aria-expanded={open} aria-controls="mobile-navigation">{open ? <X size={22} aria-hidden="true" /> : <Menu size={22} aria-hidden="true" />}</button>{open && <nav id="mobile-navigation" className="mobile-links" aria-label="Mobile navigation"><Link href="/#coverage" onClick={() => setOpen(false)}>Coverage</Link><Link href="/#live" onClick={() => setOpen(false)}>Baseline</Link><Link href="/#methodology" onClick={() => setOpen(false)}>Methodology</Link>{links}</nav>}</header>;
}
export function PublicNav() {
  return <OraNav />;
}
export function AppShell({ children }: { children: ReactNode }) {
  return <><a className="skip-link" href="#main">Skip to content</a><header className="app-header"><div className="nav-inner"><Logo /><nav aria-label="Scan navigation" className="app-links"><Link href="/#scan-tree">Scan tree</Link><Link href="/#scan">Scan your app</Link></nav></div></header><main id="main" className="page-container app-main">{children}</main><footer className="app-footer page-container"><span>Evidence before reassurance.</span><Link href="/report/sample">Explore a sample report ↗</Link></footer></>;
}
export function PageHeading({ eyebrow, title, description, action }: { eyebrow?: ReactNode; title: string; description?: ReactNode; action?: ReactNode }) {
  return <div className="page-heading"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1>{description && <div className="page-description">{description}</div>}</div>{action && <div className="heading-action">{action}</div>}</div>;
}
export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "success" | "warning" | "danger" | "info" | "category" }) {
  const label = typeof children === "string" ? children.toLowerCase() : "";
  const inferred = ["completed", "verified", "ownership verified"].includes(label) ? "success"
    : ["critical", "high", "failed"].includes(label) ? "danger"
    : ["medium", "verification needed", "unavailable", "timed out"].includes(label) ? "warning"
    : ["low", "info", "current session", "browser workspace", "running", "queued", "provisioning", "processing"].includes(label) ? "info" : "neutral";
  return <span className={`status-badge ${tone === "neutral" ? inferred : tone}`}>{children}</span>;
}
export function EmptyState({ title, description, action }: { title: string; description: ReactNode; action?: ReactNode }) {
  return <section className="empty-state"><span className="empty-mark" aria-hidden="true"><ArrowUpRight size={28} strokeWidth={1.2} /></span><h2>{title}</h2><div className="muted empty-description">{description}</div>{action && <div className="empty-action">{action}</div>}</section>;
}
export function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="notice error-notice" role="alert"><p>{message}</p>{retry && <button type="button" className="text-button" onClick={retry}>Try again</button>}</div>;
}
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  async function copy() { try { await navigator.clipboard.writeText(text); setState("copied"); } catch { setState("error"); } }
  return <span className="copy-control"><button type="button" className="text-button" onClick={copy}>{state === "copied" ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}{state === "copied" ? "Copied" : label}</button><span className="small" role="status">{state === "error" ? "Clipboard unavailable. Select the text to copy it." : ""}</span></span>;
}
