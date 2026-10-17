"use client";

import { useState } from "react";
import { Card } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import type { UiFinding, UiSeverity } from "../lib/scan-flow";
import {
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  ShieldX,
  Info,
  AlertCircle,
  Copy,
  Check,
} from "lucide-react";

const SEVERITY_ORDER: UiSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_ICON: Record<UiSeverity, typeof AlertTriangle> = {
  critical: ShieldX,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

interface FindingsListProps {
  findings: UiFinding[];
}

export default function FindingsList({ findings }: FindingsListProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState<string | null>(null);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const copyFix = (id: string, fix: string) => {
    void navigator.clipboard.writeText(fix);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-(--color-text-muted) text-sm">
        No findings yet. Start a scan to see results.
      </div>
    );
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    items: findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-6">
      {grouped.map((group) => {
        const Icon = SEVERITY_ICON[group.severity];
        return (
          <div key={group.severity}>
            <div className="flex items-center gap-2 mb-3">
              <Badge variant={group.severity as "critical" | "high" | "medium" | "low"}>
                {group.severity}
              </Badge>
              <span className="text-xs text-(--color-text-muted)">
                {group.items.length} finding{group.items.length > 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-2">
              {group.items.map((finding) => {
                const isOpen = expanded.has(finding.id);
                return (
                  <Card key={finding.id} className="p-0 overflow-hidden">
                    <button
                      type="button"
                      onClick={() => toggle(finding.id)}
                      className="w-full flex items-center justify-between px-5 py-3.5 text-left cursor-pointer hover:bg-(--color-bg-card-hover) transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <Icon className="w-4 h-4 shrink-0 opacity-60" />
                        <div>
                          <p className="text-sm font-medium text-(--color-text-primary)">
                            {finding.title}
                          </p>
                          <p className="text-[11px] text-(--color-text-muted) mt-0.5">
                            {finding.affected}
                            {finding.cwe && (
                              <span className="ml-2 opacity-60">({finding.cwe})</span>
                            )}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={finding.source === "osint" ? "accent" : "default"}>
                          {finding.source}
                        </Badge>
                        {isOpen ? (
                          <ChevronUp className="w-4 h-4 text-(--color-text-muted)" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-(--color-text-muted)" />
                        )}
                      </div>
                    </button>
                    {isOpen && (
                      <div className="px-5 pb-4 border-t border-(--color-border) pt-4 space-y-3 animate-fade-in">
                        <div>
                          <p className="text-[11px] text-(--color-text-muted) uppercase tracking-wider mb-1">
                            Summary
                          </p>
                          <p className="text-sm text-(--color-text-secondary)">{finding.summary}</p>
                        </div>
                        {finding.evidence && (
                          <div>
                            <p className="text-[11px] text-(--color-text-muted) uppercase tracking-wider mb-1">
                              Evidence
                            </p>
                            <pre className="text-xs font-mono text-(--color-text-secondary) bg-(--color-bg) rounded-lg p-3 overflow-x-auto border border-(--color-border-subtle)">
                              {finding.evidence}
                            </pre>
                          </div>
                        )}
                        {finding.fix && (
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <p className="text-[11px] text-(--color-text-muted) uppercase tracking-wider">
                                Fix
                              </p>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => copyFix(finding.id, finding.fix)}
                                className="h-6 px-2 text-[11px]"
                              >
                                {copied === finding.id ? (
                                  <>
                                    <Check className="w-3 h-3" />
                                    Copied
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    Copy
                                  </>
                                )}
                              </Button>
                            </div>
                            <pre className="text-xs font-mono text-(--color-green) bg-(--color-bg) rounded-lg p-3 overflow-x-auto border border-(--color-border-subtle)">
                              {finding.fix}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
