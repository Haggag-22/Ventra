import { CASES_HREF } from "@/lib/routes";
import { redirect } from "next/navigation";

export default function HomePage() {
  redirect(CASES_HREF);
}
