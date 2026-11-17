variable "region" {
  description = "AWS region for the security report archive"
  type        = string
  default     = "eu-central-1"
}

variable "name_prefix" {
  description = "Prefix for bucket and role names"
  type        = string
  default     = "kb-assistant-security"
}

variable "github_repository" {
  description = "owner/repo allowed to assume the CI role via GitHub OIDC"
  type        = string
  default     = "Golovastik777/devsecops-platform"
}

variable "report_retention_days" {
  description = "How long scan reports are kept"
  type        = number
  default     = 365
}
