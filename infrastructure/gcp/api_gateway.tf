# Targets: api_gateway

resource "google_endpoints_service" "lab" {
  count        = var.enable_api_gateway ? 1 : 0
  service_name = "${local.name}.endpoints.${var.project_id}.cloud.goog"

  openapi_config = <<-YAML
    swagger: "2.0"
    info:
      title: "${local.name} API"
      version: "1.0.0"
    host: "${local.name}.endpoints.${var.project_id}.cloud.goog"
    schemes:
      - "https"
    paths:
      /hello:
        get:
          summary: Hello
          operationId: hello
          x-google-backend:
            address: ${google_cloudfunctions2_function.hello.service_config[0].uri}
          responses:
            "200":
              description: OK
  YAML

  depends_on = [google_project_service.apis, google_cloudfunctions2_function.hello]
}

resource "google_api_gateway_api" "lab" {
  count      = var.enable_api_gateway ? 1 : 0
  provider   = google-beta
  api_id     = "${local.name}-api"
  depends_on = [google_project_service.apis]
}

resource "google_api_gateway_api_config" "lab" {
  count         = var.enable_api_gateway ? 1 : 0
  provider      = google-beta
  api           = google_api_gateway_api.lab[0].api_id
  api_config_id = "${local.name}-config"

  openapi_documents {
    document {
      path     = "openapi.yaml"
      contents = base64encode(google_endpoints_service.lab[0].openapi_config)
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
  count      = var.enable_api_gateway ? 1 : 0
  provider   = google-beta
  api_config = google_api_gateway_api_config.lab[0].id
  gateway_id = "${local.name}-gw"
  region     = var.region
}
