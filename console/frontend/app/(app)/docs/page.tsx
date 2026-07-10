import { redirect } from "next/navigation";
import { docsDefaultHref } from "@/lib/docs-routes";

export default function DocsHubPage() {
  redirect(docsDefaultHref());
}
