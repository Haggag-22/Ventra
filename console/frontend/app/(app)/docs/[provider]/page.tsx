import { redirect } from "next/navigation";
import { docsDefaultHref, docsSectionHref, isDocProvider } from "@/lib/docs-routes";

export default async function DocProviderIndexPage({
  params,
}: {
  params: Promise<{ provider: string }>;
}) {
  const { provider: raw } = await params;
  const provider = raw.toLowerCase();
  if (!isDocProvider(provider)) {
    redirect(docsDefaultHref());
  }
  redirect(docsSectionHref(provider, "authentication"));
}
