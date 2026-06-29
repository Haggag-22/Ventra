# API Gateway fronting the Cloud Function. Gateway request logs feed the api_gateway
# collector. Requires the function, so it is gated on both toggles.
#
# Targets: api_gateway

locals {
  apigw_enabled = var.enable_api_gateway && var.enable_functions
}

resource "google_api_gateway_api" "lab" {
  provider = google-beta
  count    = local.apigw_enabled ? 1 : 0
  api_id   = "${local.name}api"

  depends_on = [google_project_service.apis]
}

resource "google_api_gateway_api_config" "lab" {
  provider      = google-beta
  count         = local.apigw_enabled ? 1 : 0
  api           = google_api_gateway_api.lab[0].api_id
  api_config_id = "${local.name}config${local.token}"

  openapi_documents {
    document {
      path = "openapi.yaml"
      contents = base64encode(<<-YAML
        swagger: "2.0"
        info:
          title: ${local.name} api
          version: 1.0.0
        schemes:
          - https
        produces:
          - application/json
        paths:
          /hello:
            get:
              summary: Hello
              operationId: hello
              x-google-backend:
                address: ${google_cloudfunctions2_function.hello[0].service_config[0].uri}
              responses:
                "200":
                  description: OK
        YAML
      )
    }
  }

  gateway_config {
    backend_config {
      google_service_account = google_service_account.lab.email
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_api_gateway_gateway" "lab" {
  provider   = google-beta
  count      = local.apigw_enabled ? 1 : 0
  api_config = google_api_gateway_api_config.lab[0].id
  gateway_id = "${local.name}gateway"
  region     = var.region

  depends_on = [google_project_service.apis]
}
