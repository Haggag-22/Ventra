/** Parse ELB/ALB and CloudFront raw access-log lines into labeled fields for the drawer. */

const TOKEN_RE = /\[[^\]]*\]|"[^"]*"|\S+/g;

const ALB_TYPES = new Set(["http", "https", "h2", "grpcs", "ws", "wss", "tls"]);

const CLOUDFRONT_DEFAULT_FIELDS =
  "date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status " +
  "cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type " +
  "x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for " +
  "ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status " +
  "fle-encrypted-fields c-port time-to-first-byte x-edge-detailed-result-type " +
  "sc-content-type sc-content-len sc-range-start sc-range-end";

const ALB_FIELD_LABELS = [
  "Type",
  "Time",
  "Load balancer",
  "Client",
  "Target",
  "Request processing (s)",
  "Target processing (s)",
  "Response processing (s)",
  "ELB status",
  "Target status",
  "Received bytes",
  "Sent bytes",
  "Request",
  "User agent",
  "SSL cipher",
  "SSL protocol",
  "Target group",
  "Trace ID",
  "Domain",
  "Certificate ARN",
  "Rule priority",
  "Request creation time",
  "Actions executed",
  "Redirect URL",
  "Error reason",
  "Target list",
  "Target status list",
  "Classification",
  "Classification reason",
];

const CLB_FIELD_LABELS = [
  "Time",
  "Load balancer",
  "Client",
  "Target",
  "Request processing (s)",
  "Backend processing (s)",
  "Response processing (s)",
  "Backend status",
  "ELB status",
  "Received bytes",
  "Sent bytes",
  "Request",
  "User agent",
  "SSL cipher",
  "SSL protocol",
];

export interface AccessLogField {
  label: string;
  value: string;
}

function tokenize(line: string): string[] {
  const matches = line.match(TOKEN_RE);
  if (!matches) return [];
  return matches.map((t) => (t.startsWith('"') ? t.slice(1, -1) : t));
}

function isEmptyValue(value: string): boolean {
  return value === "" || value === "-" || value === "-1";
}

/** Drop trailing empty placeholders; keep meaningful middle gaps (e.g. missing UA). */
function trimTrailingEmpty(fields: AccessLogField[]): AccessLogField[] {
  let end = fields.length;
  while (end > 0 && isEmptyValue(fields[end - 1].value)) end -= 1;
  return fields.slice(0, end);
}

export function parseAccessLogLine(
  line: string,
  source: string,
  rawRecord?: Record<string, unknown>,
): AccessLogField[] | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  if (source === "cloudfront") {
    const header = String(rawRecord?.fields ?? CLOUDFRONT_DEFAULT_FIELDS);
    const names = header.split(/\s+/).filter(Boolean);
    const values = trimmed.split("\t");
    if (values.length < 2) return null;
    return trimTrailingEmpty(
      values.map((value, i) => ({
        label: names[i] ?? `Field ${i + 1}`,
        value: isEmptyValue(value) ? "—" : value,
      })),
    );
  }

  if (source === "elb_alb") {
    const tokens = tokenize(trimmed);
    if (tokens.length < 12) return null;
    const labels = ALB_TYPES.has(tokens[0]) ? ALB_FIELD_LABELS : CLB_FIELD_LABELS;
    return trimTrailingEmpty(
      tokens.map((value, i) => ({
        label: labels[i] ?? `Field ${i + 1}`,
        value: isEmptyValue(value) ? "—" : value,
      })),
    );
  }

  return null;
}
