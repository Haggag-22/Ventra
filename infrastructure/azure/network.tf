# Targets: vnet_flow, nsg_flow, azure_firewall, app_gateway, dns

resource "azurerm_virtual_network" "lab" {
  name                = "${local.name}-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_subnet" "public" {
  name                 = "public"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 0)]
}

resource "azurerm_subnet" "private" {
  name                 = "private"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 1)]
}

resource "azurerm_subnet" "firewall" {
  count                = var.enable_firewall ? 1 : 0
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 2)]
}

resource "azurerm_subnet" "appgw" {
  count                = var.enable_app_gateway ? 1 : 0
  name                 = "appgw"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 4, 3)]
}

resource "azurerm_network_security_group" "lab" {
  name                = "${local.name}-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_network_security_rule" "allow_http" {
  name                        = "allow-http"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.lab.name
  network_security_group_name = azurerm_network_security_group.lab.name
}

resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

resource "azurerm_network_watcher" "lab" {
  name                = "${local.name}-nw"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_public_ip" "lab" {
  name                = "${local.name}-pip"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "web" {
  name                = "${local.name}-nic"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.private.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.lab.id
  }
}

resource "azurerm_linux_virtual_machine" "web" {
  name                  = "${local.name}-vm"
  resource_group_name   = azurerm_resource_group.lab.name
  location              = azurerm_resource_group.lab.location
  size                  = var.vm_size
  admin_username        = "azureuser"
  network_interface_ids = [azurerm_network_interface.web.id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.ssh.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(<<-CLOUD
    #!/bin/bash
    apt-get update && apt-get install -y nginx
    echo ventra-lab > /var/www/html/index.html
  CLOUD
  )
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_public_ip" "firewall" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${local.name}-fw-pip"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_firewall" "lab" {
  count               = var.enable_firewall ? 1 : 0
  name                = "${local.name}-fw"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.firewall[0].id
    public_ip_address_id = azurerm_public_ip.firewall[0].id
  }
}

resource "azurerm_monitor_diagnostic_setting" "firewall" {
  count                      = var.enable_firewall ? 1 : 0
  name                       = "${local.name}-fw-diag"
  target_resource_id         = azurerm_firewall.lab[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  storage_account_id         = azurerm_storage_account.logs.id

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_dns_zone" "lab" {
  name                = "${local.name}.test"
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_dns_a_record" "web" {
  name                = "www"
  zone_name           = azurerm_dns_zone.lab.name
  resource_group_name = azurerm_resource_group.lab.name
  ttl                 = 300
  records             = [azurerm_public_ip.lab.ip_address]
}
