output "reports_bucket" {
  description = "Bucket for scan reports and SBOMs"
  value       = aws_s3_bucket.reports.bucket
}

output "ci_role_arn" {
  description = "Role assumed by GitHub Actions via OIDC"
  value       = aws_iam_role.ci_reports.arn
}
