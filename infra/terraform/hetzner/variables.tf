variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "fsn1"
}

variable "server_type" {
  description = "Server type for the security tooling host (DefectDojo, Wazuh manager)"
  type        = string
  default     = "cx32"
}

variable "admin_ssh_public_key" {
  description = "Public key of the operator; password login is disabled"
  type        = string
}

variable "admin_cidrs" {
  description = "Networks allowed to reach SSH (VPN / office)"
  type        = list(string)
  validation {
    condition     = length(var.admin_cidrs) > 0 && !contains(var.admin_cidrs, "0.0.0.0/0") && !contains(var.admin_cidrs, "::/0")
    error_message = "SSH must not be open to the whole internet."
  }
}

variable "dashboard_cidrs" {
  description = "Networks allowed to reach the HTTPS dashboards and Wazuh agent ports"
  type        = list(string)
}
