import { redirect } from "next/navigation";

/** Saved kits moved to Collection kit → Saved kits. */
export default function ProfilesRedirectPage() {
  redirect("/collection-kits");
}
