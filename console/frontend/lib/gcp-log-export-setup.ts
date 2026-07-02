/** Setup copy for BigQuery Export and GCS Archive (shown in Acquire UI). */

export type GcpLogExportSetupKind = "bigquery" | "gcs";

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
  bigquery: {
    title: "BigQuery Export setup",
    intro:
      "Ventra is read-only. The client admin routes logs to BigQuery before collection runs.",
    steps: [
      {
        title: "Create a dataset",
        body: "Create or choose a BigQuery dataset (e.g. my-project.audit_logs).",
      },
      {
        title: "Create a log sink",
        body: "Create a log sink that exports the log types you need to that dataset.",
      },
      {
        title: "Grant read access",
        body: "Grant the Ventra service account bigquery.jobs.create, bigquery.datasets.get, bigquery.tables.get, bigquery.tables.getData, and bigquery.tables.list on the dataset.",
      },
    ],
    commands: `# Create dataset
bq mk --dataset PROJECT:DATASET

# Export admin activity logs (adjust filter as needed)
gcloud logging sinks create ventra-audit-export \\
  bigquery.googleapis.com/projects/PROJECT/datasets/DATASET \\
  --log-filter='logName:"cloudaudit.googleapis.com"' \\
  --project=PROJECT

# Grant sink writer on the dataset (see writer_identity from describe)
# gcloud logging sinks describe ventra-audit-export --project=PROJECT`,
    footnote:
      "The kit includes SETUP-gcp-log-export-bigquery.md with these steps for the client.",
  },
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
