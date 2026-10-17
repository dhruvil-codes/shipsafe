import Link from "next/link";
import { Badge } from "@/components/product-ui";
import { dateLabel, type ScanRecord } from "./data";

/** Recorded assessments only; absent scores remain visibly unassessed. */
export function ScanTable({ scans }: { scans: ScanRecord[] }) {
  return <div style={{ overflowX: "auto" }}><table className="data-table">
    <caption className="sr-only">Recorded security assessments</caption>
    <thead><tr><th scope="col">Assessment</th><th scope="col">Status</th><th scope="col">Score</th><th scope="col">Coverage</th><th scope="col">Created</th><th scope="col"><span className="sr-only">Open assessment</span></th></tr></thead>
    <tbody>{scans.map((scan) => <tr key={scan.id}>
      <td><Link href={`/projects/${scan.projectId}`}>{scan.projectName || scan.url}</Link><div className="muted small">Baseline</div></td>
      <td><Badge tone={scan.status === "COMPLETED" ? "success" : scan.status === "FAILED" ? "danger" : "neutral"}>{scan.status.toLowerCase().replaceAll("_", " ")}</Badge></td>
      <td>{scan.score === undefined ? "—" : `${scan.score}/100`}</td>
      <td>{scan.coverage === undefined ? "—" : `${scan.coverage}%`}</td>
      <td className="muted small">{dateLabel(scan.createdAt)}</td>
      <td><Link href={`/${scan.status === "COMPLETED" ? "report" : "scan"}/${scan.id}`} aria-label={`View assessment for ${scan.projectName || scan.url}`}>View →</Link></td>
    </tr>)}</tbody>
  </table></div>;
}
