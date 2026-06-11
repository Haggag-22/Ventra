import { redirect } from "next/navigation";

export default function CaseIndex({ params }: { params: { caseId: string } }) {
  redirect(`/cases/${params.caseId}/overview`);
}
