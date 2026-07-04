import { redirect } from "next/navigation";

/** Legacy bookmark — kit builder lives under Configuration → Acquire. */
export default function AcquireRedirectPage({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>;
}) {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (value == null) continue;
    if (Array.isArray(value)) value.forEach((v) => sp.append(key, v));
    else sp.set(key, value);
  }
  const q = sp.toString();
  redirect(q ? `/config/acquire?${q}` : "/config/acquire");
}
