export type CheckState = "pending" | "running" | "passed" | "failed";

export interface CheckItem {
  id: string;
  name: string;
  detail: string;
  state: CheckState;
}

const STATE_LABEL: Record<CheckState, string> = {
  pending: "Pending",
  running: "Running",
  passed: "Passed",
  failed: "Failed",
};

const STATE_BADGE: Record<CheckState, string> = {
  pending: "ss-badge-neutral",
  running: "ss-badge-medium",
  passed: "ss-badge-pass",
  failed: "ss-badge-fail",
};

/** Live agent verification checklist (TLS, headers, files, ports). */
export default function Checklist({ items }: { items: CheckItem[] }) {
  return (
    <ul className="ss-check-list" aria-live="polite">
      {items.map((item) => (
        <li key={item.id} className="ss-check-item">
          <span
            className={`ss-check-dot ss-check-${item.state}`}
            aria-hidden="true"
          />
          <div>
            <p className="ss-check-name">{item.name}</p>
            <p className="ss-check-detail">{item.detail}</p>
          </div>
          <span className={`ss-check-state ss-badge ${STATE_BADGE[item.state]}`}>
            {STATE_LABEL[item.state]}
          </span>
        </li>
      ))}
    </ul>
  );
}
