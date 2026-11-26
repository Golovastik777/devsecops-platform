terraform {
  required_version = ">= 1.9"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.109.0"
    }
  }
}

# Token comes from DIGITALOCEAN_TOKEN in the environment.
provider "digitalocean" {}
