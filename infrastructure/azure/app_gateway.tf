# Targets: app_gateway, front_door

resource "azurerm_public_ip" "appgw" {
  count               = var.enable_app_gateway ? 1 : 0
  name                = "${local.name}-appgw-pip"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_application_gateway" "lab" {
  count               = var.enable_app_gateway ? 1 : 0
  name                = "${local.name}-appgw"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 1
  }

  gateway_ip_configuration {
    name      = "gw-ip"
    subnet_id = azurerm_subnet.appgw[0].id
  }

  frontend_port {
    name = "http"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = azurerm_public_ip.appgw[0].id
  }

  backend_address_pool {
    name         = "web"
    ip_addresses = [azurerm_network_interface.web.private_ip_address]
  }

  backend_http_settings {
    name                  = "http"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 30
  }

  http_listener {
    name                           = "http"
    frontend_ip_configuration_name = "public"
    frontend_port_name             = "http"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "route"
    rule_type                  = "Basic"
    http_listener_name         = "http"
    backend_address_pool_name  = "web"
    backend_http_settings_name = "http"
    priority                   = 100
  }
}

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  count                      = var.enable_app_gateway ? 1 : 0
  name                       = "${local.name}-appgw-diag"
  target_resource_id         = azurerm_application_gateway.lab[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_cdn_frontdoor_profile" "lab" {
  count               = var.enable_front_door ? 1 : 0
  name                = "${local.name}-fd"
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Standard_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "lab" {
  count                    = var.enable_front_door ? 1 : 0
  name                     = "${local.name}-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.lab[0].id
}

resource "azurerm_cdn_frontdoor_origin_group" "lab" {
  count                    = var.enable_front_door ? 1 : 0
  name                     = "origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.lab[0].id

  load_balancing {}
}

resource "azurerm_cdn_frontdoor_origin" "lab" {
  count                         = var.enable_front_door ? 1 : 0
  name                          = "web-origin"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.lab[0].id
  enabled                       = true
  host_name                     = azurerm_public_ip.lab.fqdn
  certificate_name_check_enabled = true
  origin_host_header            = azurerm_public_ip.lab.fqdn
  http_port                     = 80
  https_port                    = 443
}

resource "azurerm_cdn_frontdoor_route" "lab" {
  count                         = var.enable_front_door ? 1 : 0
  name                          = "default-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.lab[0].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.lab[0].id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.lab[0].id]
  enabled                       = true
  forwarding_protocol           = "HttpOnly"
  https_redirect_enabled        = true
  patterns_to_match             = ["/*"]
  supported_protocols           = ["Http", "Https"]
  link_to_default_domain        = true
}

resource "azurerm_monitor_diagnostic_setting" "frontdoor" {
  count                      = var.enable_front_door ? 1 : 0
  name                       = "${local.name}-fd-diag"
  target_resource_id         = azurerm_cdn_frontdoor_profile.lab[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category_group = "allLogs"
  }
}
