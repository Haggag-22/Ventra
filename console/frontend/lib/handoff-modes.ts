export type HandoffMode = "file" | "s3_ir_bucket" | "presigned";

export type HandoffModeInfo = {
  id: HandoffMode;
  label: string;
  summary: string;
  clientNote: string;
  analystNote: string;
};

export const HANDOFF_MODES: HandoffModeInfo[] = [
  {
    id: "file",
    label: "Client sends file",
    summary: "Client returns the sealed .tar.zst to you (email, SFTP, secure share).",
    clientNote: "Kit writes locally; client sends you the sealed package.",
    analystNote: "Use Import package on Cases when the file arrives.",
  },
  {
    id: "s3_ir_bucket",
    label: "Upload to my IR bucket",
    summary: "Client kit uploads to your S3 bucket. You poll with Import from S3.",
    clientNote: "Client needs write access to your bucket prefix (cross-account IAM).",
    analystNote: "Set VENTRA_INGEST_S3_PREFIX on your Ventra server to the same prefix.",
  },
  {
    id: "presigned",
    label: "Presigned URL to my bucket",
    summary: "You give a one-time upload URL; client uploads without your AWS keys.",
    clientNote: "Paste a presigned PUT URL into the kit (no bucket IAM for client).",
    analystNote: "Ingest from your bucket after upload (Import from S3 or Import package).",
  },
];

export function handoffModeLabel(id: string): string {
  return HANDOFF_MODES.find((m) => m.id === id)?.label ?? id;
}

export function parseHandoffMode(raw: string | null | undefined): HandoffMode {
  const v = (raw || "file") as HandoffMode;
  return HANDOFF_MODES.some((m) => m.id === v) ? v : "file";
}

export function buildTransportSpec(
  mode: HandoffMode,
  bucket: string,
  prefix: string,
  presignedUrl: string,
): string {
  if (mode === "file") return "";
  if (mode === "presigned") {
    const url = presignedUrl.trim();
    return url ? `s3-presigned:${url}` : "";
  }
  const b = bucket.trim();
  if (!b) return "";
  const p = prefix.trim().replace(/^\/+|\/+$/g, "");
  return p ? `s3://${b}/${p}/` : `s3://${b}/`;
}
