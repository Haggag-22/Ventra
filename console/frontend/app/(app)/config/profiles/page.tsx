import { redirect } from "next/navigation";

/** Saved kits moved to Collection kits → Saved Kits. */
export default function ProfilesRedirectPage() {
  redirect("/collection-kits");
}
