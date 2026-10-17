"use client";

import Link from "next/link";
import { ChevronDown } from "lucide-react";
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import InlineScan from "./InlineScan";

export function ScanForm({ variant: _variant }: { variant?: "hero" | "stage" | "ora" }) {
  return <InlineScan />;
}

export function FindingTabs({ evidence, fix, href }: { evidence: ReactNode; fix: ReactNode; href: string }) {
  const [active, setActive] = useState(0);
  const baseId = useId();
  const tabIds = [`${baseId}-tab-evidence`, `${baseId}-tab-fix`];
  const panelIds = [`${baseId}-panel-evidence`, `${baseId}-panel-fix`];
  const evidenceTabRef = useRef<HTMLButtonElement>(null);
  const fixTabRef = useRef<HTMLButtonElement>(null);

  function focusTab(index: number) {
    (index === 0 ? evidenceTabRef.current : fixTabRef.current)?.focus();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    let next: number | null = null;
    if (event.key === "ArrowRight" || event.key === "ArrowLeft") next = (active + 1) % 2;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = 1;
    if (next !== null) {
      event.preventDefault();
      setActive(next);
      focusTab(next);
    }
  }

  return (
    <div className="finding-explorer">
      <div className="finding-controls">
        <div className="seg" role="tablist" aria-label="Explore a recorded finding" data-active={active === 0 ? "evidence" : "fix"}>
          <span className="seg-pill" aria-hidden="true" />
          <button
            ref={evidenceTabRef}
            type="button"
            role="tab"
            id={tabIds[0]}
            aria-selected={active === 0}
            aria-controls={panelIds[0]}
            tabIndex={active === 0 ? 0 : -1}
            onClick={() => setActive(0)}
            onKeyDown={handleKeyDown}
          >
            Evidence
          </button>
          <button
            ref={fixTabRef}
            type="button"
            role="tab"
            id={tabIds[1]}
            aria-selected={active === 1}
            aria-controls={panelIds[1]}
            tabIndex={active === 1 ? 0 : -1}
            onClick={() => setActive(1)}
            onKeyDown={handleKeyDown}
          >
            Fix
          </button>
        </div>
        <Link href={href} className="text-link finding-link">
          Full finding <span aria-hidden="true">↗</span>
        </Link>
      </div>
      <div className="finding-content" role="tabpanel" id={panelIds[0]} aria-labelledby={tabIds[0]} hidden={active !== 0} tabIndex={0}>
        {evidence}
      </div>
      <div className="finding-content" role="tabpanel" id={panelIds[1]} aria-labelledby={tabIds[1]} hidden={active !== 1} tabIndex={0}>
        {fix}
      </div>
    </div>
  );
}

export function LimitsAccordion({ items }: { items: { q: string; a: ReactNode }[] }) {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const baseId = useId();
  const buttonRefs = useRef<(HTMLButtonElement | null)[]>([]);

  function handleItemKeyDown(event: KeyboardEvent<HTMLDivElement>, index: number) {
    if (event.key === "Escape" && openIndex === index) {
      event.stopPropagation();
      setOpenIndex(null);
      buttonRefs.current[index]?.focus();
    }
  }

  return (
    <div className="acc">
      {items.map((item, index) => {
        const open = openIndex === index;
        const buttonId = `${baseId}-button-${index}`;
        const panelId = `${baseId}-panel-${index}`;
        return (
          <div className="acc-item" key={index} onKeyDown={(event) => handleItemKeyDown(event, index)}>
            <button
              ref={(element) => {
                buttonRefs.current[index] = element;
              }}
              type="button"
              className="acc-btn"
              id={buttonId}
              aria-expanded={open}
              aria-controls={panelId}
              onClick={() => setOpenIndex(open ? null : index)}
            >
              <span>{item.q}</span>
              <ChevronDown className="acc-chev" size={18} aria-hidden="true" />
            </button>
            <div className="acc-panel" role="region" id={panelId} aria-labelledby={buttonId} hidden={!open}>
              <div className="acc-body">{item.a}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
