import { redirect } from "next/navigation";

export default function CaseSettingsRedirect({ params }: { params: { caseId: string } }) {
  redirect("/settings");
}
