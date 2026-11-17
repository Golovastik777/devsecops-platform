# Application cluster (DOKS) in a private VPC.

data "digitalocean_kubernetes_versions" "this" {
  version_prefix = var.k8s_minor_version
}

resource "digitalocean_vpc" "app" {
  name     = "kb-assistant-${var.region}"
  region   = var.region
  ip_range = "10.50.0.0/16"
}

resource "digitalocean_kubernetes_cluster" "app" {
  name          = "kb-assistant"
  region        = var.region
  version       = data.digitalocean_kubernetes_versions.this.latest_version
  vpc_uuid      = digitalocean_vpc.app.id
  auto_upgrade  = true
  surge_upgrade = true
  ha            = true

  maintenance_policy {
    day        = "sunday"
    start_time = "03:00"
  }

  node_pool {
    name       = "default"
    size       = var.node_size
    auto_scale = true
    min_nodes  = 2
    max_nodes  = 4
    tags       = ["kb-assistant"]
  }
}
