// Display formatters. Timestamps are rendered in UTC — forensic work is UTC-first.

export function fmtBytes(n: number | null | undefined): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtNum(n: number | null | undefined): string {
  return (n ?? 0).toLocaleString("en-US");
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(".000Z", "Z").replace("Z", " UTC");
}

export function fmtTimeShort(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const s = d.toISOString();
  return `${s.slice(5, 10)} ${s.slice(11, 19)}`;
}

/** CloudTrail table: full UTC timestamp with Z suffix (e.g. 2026-06-10 18:20:20Z). */
export function fmtTimeCloudTrail(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

export function fmtDateOnly(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}

export function relativeSpan(a: string | null, b: string | null): string {
  if (!a || !b) return "—";
  const ms = new Date(b).getTime() - new Date(a).getTime();
  if (isNaN(ms)) return "—";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins} min`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48) return `${hrs} hr`;
  return `${Math.round(hrs / 24)} days`;
}

export function shortArn(arn: string): string {
  if (!arn) return "";
  if (arn.startsWith("arn:")) {
    const parts = arn.split(":");
    return parts[parts.length - 1].replace(/^.*\//, (m) => m); // keep resource portion
  }
  return arn;
}

export function titleCase(s: string): string {
  return s.replace(/(^|_)([a-z])/g, (_, p1, c) => (p1 ? " " : "") + c.toUpperCase());
}
