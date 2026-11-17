variable "region" {
  description = "DigitalOcean region for the application cluster"
  type        = string
  default     = "fra1"
}

variable "k8s_minor_version" {
  description = "Kubernetes minor version prefix, e.g. 1.36."
  type        = string
  default     = "1.36."
}

variable "node_size" {
  description = "Droplet size for worker nodes"
  type        = string
  default     = "s-2vcpu-4gb"
}
