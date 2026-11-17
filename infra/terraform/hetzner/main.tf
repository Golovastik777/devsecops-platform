# Security tooling host: DefectDojo + Wazuh manager.
# Hardened further by infra/ansible/hardening.yml after provisioning.

resource "hcloud_ssh_key" "admin" {
  name       = "kb-assistant-admin"
  public_key = var.admin_ssh_public_key
}

resource "hcloud_network" "security" {
  name     = "security-tools"
  ip_range = "10.40.0.0/16"
}

resource "hcloud_network_subnet" "security" {
  network_id   = hcloud_network.security.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.40.1.0/24"
}

resource "hcloud_firewall" "security_tools" {
  name = "security-tools"

  rule {
    description = "SSH from admin networks only"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.admin_cidrs
  }

  rule {
    description = "HTTPS dashboards (DefectDojo, Wazuh)"
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = var.dashboard_cidrs
  }

  rule {
    description = "Wazuh agent enrollment and events"
    direction   = "in"
    protocol    = "tcp"
    port        = "1514-1515"
    source_ips  = var.dashboard_cidrs
  }
}

resource "hcloud_server" "security_tools" {
  name               = "security-tools-1"
  image              = "ubuntu-24.04"
  server_type        = var.server_type
  location           = var.location
  ssh_keys           = [hcloud_ssh_key.admin.id]
  firewall_ids       = [hcloud_firewall.security_tools.id]
  backups            = true
  delete_protection  = true
  rebuild_protection = true

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_ssh_public_key = var.admin_ssh_public_key
  })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.security.id
    ip         = "10.40.1.10"
  }

  depends_on = [hcloud_network_subnet.security]
}
