import ReportView from "@/components/assessment/report";

export default async function FindingPage({ params }: { params: Promise<{ id: string; findingId: string }> }) {
  const { id, findingId } = await params;
  return <ReportView id={id} findingId={findingId} />;
}
