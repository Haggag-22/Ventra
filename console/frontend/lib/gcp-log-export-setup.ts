/** Setup copy for GCS Archive (shown in Acquire UI). */

export type GcpLogExportSetupKind = "gcs";

export type GcpLogExportSetupStep = {
  title: string;
  body: string;
};

export type GcpLogExportSetupGuide = {
  title: string;
  intro: string;
  steps: GcpLogExportSetupStep[];
  commands: string;
  footnote: string;
};

export const GCP_LOG_EXPORT_SETUP: Record<GcpLogExportSetupKind, GcpLogExportSetupGuide> = {
  gcs: {
    title: "Cloud Storage Archive setup",
    intro:
      "Ventra is read-only. The client admin routes logs to a GCS bucket before collection runs.",
    steps: [
      {
        title: "Create a bucket",
        body: "Create or choose a GCS bucket (e.g. gs://company-log-archive).",
      },
      {
        title: "Create a log sink",
        body: "Create a log sink that exports required log types to that bucket.",
      },
      {
        title: "Grant read access",
        body: "Grant the Ventra service account storage.buckets.get, storage.objects.list, and storage.objects.get on the bucket.",
      },
    ],
    commands: `gsutil mb -p PROJECT gs://BUCKET

gcloud logging sinks create ventra-log-archive \\
  storage.googleapis.com/BUCKET \\
  --log-filter='logName:"cloudaudit.googleapis.com"' \\
  --project=PROJECT

# Grant the sink writer service account access to the bucket
# gcloud logging sinks describe ventra-log-archive --project=PROJECT`,
    footnote:
      "The kit includes SETUP-gcp-log-export-gcs.md with these steps for the client.",
  },
};
