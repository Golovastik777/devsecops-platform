terraform {
  required_version = ">= 1.9"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.60"
    }
  }
}

# Token comes from HCLOUD_TOKEN in the environment, never from a tfvars file.
provider "hcloud" {}
