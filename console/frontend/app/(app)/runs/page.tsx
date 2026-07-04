import { CONFIG_COLLECTION_HREF } from "@/lib/routes";
import { redirect } from "next/navigation";

/** Legacy route — bookmarks to /runs land on Collection. */
export default function RunsRedirectPage() {
  redirect(CONFIG_COLLECTION_HREF);
}
