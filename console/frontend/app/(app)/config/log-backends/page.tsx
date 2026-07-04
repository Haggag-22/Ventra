import { redirect } from "next/navigation";

/** GCP log backend is configured per kit on Acquire. */
export default function LogBackendsRedirectPage() {
  redirect("/config/acquire?cloud=gcp");
}
