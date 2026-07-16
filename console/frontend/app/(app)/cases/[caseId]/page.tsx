import { DEFAULT_CASE_PANEL } from "@/lib/routes";
import { redirect } from "next/navigation";

export default function CaseIndex({ params }: { params: { caseId: string } }) {
  redirect(`/cases/${params.caseId}/${DEFAULT_CASE_PANEL}`);
}
