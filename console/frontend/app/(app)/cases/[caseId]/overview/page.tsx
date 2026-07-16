import { DEFAULT_CASE_PANEL } from "@/lib/routes";
import { redirect } from "next/navigation";

/** Legacy route — cases open on the audit timeline, not overview. */
export default function OverviewRedirect({ params }: { params: { caseId: string } }) {
  redirect(`/cases/${params.caseId}/${DEFAULT_CASE_PANEL}`);
}
