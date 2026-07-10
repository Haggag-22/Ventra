import { acquireRunHref } from "@/lib/routes";
import { readLastConnection } from "@/lib/provider-storage";
import { redirect } from "next/navigation";

/** Legacy route — bookmarks land on Acquire run mode. */
export default function NewRunRedirectPage() {
  redirect(acquireRunHref(readLastConnection()));
}
