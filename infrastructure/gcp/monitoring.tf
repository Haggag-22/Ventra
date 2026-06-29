# Cloud Monitoring alert policy + email notification channel.
#
# Targets: cloud_monitoring

resource "google_monitoring_notification_channel" "email" {
  display_name = "${local.name}email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }

  depends_on = [null_resource.apis_ready]
}

resource "google_monitoring_alert_policy" "cpu" {
  display_name = "${local.name}cpu"
  combiner     = "OR"

  conditions {
    display_name = "VM CPU high"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.9
      duration        = "60s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
  depends_on            = [null_resource.apis_ready]
}
