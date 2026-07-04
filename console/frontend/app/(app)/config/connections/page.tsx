import { CONFIG_PROVIDERS_HREF } from "@/lib/routes";
import { redirect } from "next/navigation";

/** Legacy route — bookmarks to /config/connections land on Providers. */
export default function ConnectionsRedirectPage() {
  redirect(CONFIG_PROVIDERS_HREF);
}
