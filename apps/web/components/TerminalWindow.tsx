"use client";

import type { ReactNode } from "react";

export type VmStatus = "ready" | "provisioning" | "active" | "executing" | "torn-down";

const VM_LABEL: Record<VmStatus, string> = {
  ready: "VM READY",
  provisioning: "PROVISIONING",
  active: "VM ACTIVE",
  executing: "EXECUTING",
  "torn-down": "TORN DOWN",
};

interface TerminalWindowProps {
  sandboxId: string;
  vmStatus: VmStatus;
  onNewScan: () => void;
  scanning: boolean;
  children: ReactNode;
}

/** Mac-style terminal frame with the InstaBox hero telemetry header. */
export default function TerminalWindow({
  sandboxId,
  vmStatus,
  onNewScan,
  scanning,
  children,
}: TerminalWindowProps) {
  return (
    <div className="term-grid-bg">
      <div className="term-window" role="region" aria-label="ShipSafe scan terminal">
        <div className="term-titlebar">
          <span className="term-dots" aria-hidden="true">
            <span className="term-dot term-dot-red" />
            <span className="term-dot term-dot-yellow" />
            <span className="term-dot term-dot-green" />
          </span>
          <span className="term-title" aria-live="polite">
            shipsafe-agent@instabox-vm [4 vCPU · 8GB RAM · Debian 13 · KVM Sandbox]
            <span className="term-sandbox"> {sandboxId}</span>
            <span className={`term-vm term-vm-${vmStatus}`}>
              <span className="term-pulse" aria-hidden="true" />
              {VM_LABEL[vmStatus]}
            </span>
          </span>
          <button
            type="button"
            className="term-newscan"
            onClick={onNewScan}
            disabled={scanning}
            title="Reset to a fresh scan"
          >
            New Scan
          </button>
        </div>
        <div className="term-body">{children}</div>
      </div>
    </div>
  );
}
