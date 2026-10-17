"use client";

import { Card, CardHeader, CardTitle, CardDescription } from "./ui/card";
import { Badge } from "./ui/badge";
import type { EngineCheck } from "../lib/scan-flow";
import {
  Search,
  Globe,
  ShieldAlert,
  Mail,
  FileText,
  Lock,
  type LucideIcon,
} from "lucide-react";

const ENGINE_ICONS: Record<string, LucideIcon> = {
  "dns-email": Mail,
  "attack-surface": Globe,
  tls: Lock,
  headers: ShieldAlert,
  files: FileText,
};

interface EngineListProps {
  engines: EngineCheck[];
}

/**
 * Vertical list of scan engines with status badges — bydhruvil.in "Projects" style.
 */
export default function EngineList({ engines }: EngineListProps) {
  return (
    <div className="space-y-2">
      {engines.map((engine) => {
        const Icon = ENGINE_ICONS[engine.id] ?? Search;
        const statusVariant =
          engine.state === "passed"
            ? "passed"
            : engine.state === "warning"
              ? "high"
              : engine.state === "running"
                ? "accent"
                : "default";
        const statusLabel =
          engine.state === "passed"
            ? "Passed"
            : engine.state === "warning"
              ? "Warning"
              : engine.state === "running"
                ? "Running"
                : "Pending";

        return (
          <Card key={engine.label} className="p-0">
            <div className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-(--color-accent-muted) flex items-center justify-center">
                  <Icon className="w-4 h-4 text-(--color-accent)" />
                </div>
                <div>
                  <CardTitle className="text-sm">{engine.label}</CardTitle>
                  <CardDescription className="text-[11px] mt-0.5">
                    {engine.state === "running"
                      ? "Executing on micro-VM..."
                      : engine.state === "passed"
                        ? "Completed successfully"
                        : engine.state === "warning"
                          ? "Findings detected"
                          : "Queued"}
                  </CardDescription>
                </div>
              </div>
              <Badge variant={statusVariant}>
                {engine.state === "running" && (
                  <span className="w-1.5 h-1.5 rounded-full bg-(--color-accent) animate-pulse" />
                )}
                {statusLabel}
              </Badge>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
