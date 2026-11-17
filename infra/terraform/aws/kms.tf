data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms" {
  # In a key policy "*" means "this key" - there is no other resource to scope to.
  #checkov:skip=CKV_AWS_109:Key policy; account root keeps administration so the key cannot become unmanageable
  #checkov:skip=CKV_AWS_111:Key policy; resource "*" refers to this key only
  #checkov:skip=CKV_AWS_356:Key policy; resource "*" refers to this key only
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid       = "CiReportWriter"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ci_reports.arn]
    }
  }
}

resource "aws_kms_key" "reports" {
  description             = "Encrypts security scan reports"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "reports" {
  name          = "alias/${var.name_prefix}-reports"
  target_key_id = aws_kms_key.reports.key_id
}
