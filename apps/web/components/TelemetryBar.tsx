export type SandboxStatus =
  | "provisioning"
  | "active"
  | "executing"
  | "torn-down";

const STATUS_LABEL: Record<SandboxStatus, string> = {
  provisioning: "Provisioning",
  active: "Micro-VM Active",
  executing: "Agent Executing",
  "torn-down": "Torn Down",
};

interface TelemetryBarProps {
  sandboxId: string;
  status: SandboxStatus;
}

/** InstaBox hero strip: sandbox identity, VM specs, lifecycle pill. */
export default function TelemetryBar({ sandboxId, status }: TelemetryBarProps) {
  return (
    <div className="ss-telemetry" aria-live="polite">
      <span className="ss-sandbox-id" title="InstaBox sandbox ID">
        {sandboxId}
      </span>
      <span className="ss-specs">4 vCPU · 8 GiB RAM · Linux Debian 13</span>
      <span className="ss-telemetry-spacer" />
      <span className={`ss-pill ss-pill-${status}`}>
        <span className="ss-dot" aria-hidden="true" />
        {STATUS_LABEL[status]}
      </span>
    </div>
  );
}
