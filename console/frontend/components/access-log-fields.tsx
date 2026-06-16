"use client";

import type { AccessLogField } from "@/lib/access-log-format";

export function AccessLogFields({ fields }: { fields: AccessLogField[] }) {
  return (
    <dl className="ct-access-log-fields">
      {fields.map((f, i) => (
        <div key={`${f.label}-${i}`} className="ct-access-log-row">
          <dt className="ct-access-log-label" title={f.label}>
            {f.label}
          </dt>
          <dd className="ct-access-log-value">{f.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function WrappedLogLine({ line }: { line: string }) {
  return <pre className="ct-log-wrap">{line}</pre>;
}
