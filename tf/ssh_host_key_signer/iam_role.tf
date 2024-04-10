data "aws_iam_policy_document" "policy" {
  statement {
    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
    ]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_kms_key" "lambda" {
  key_id = "alias/aws/lambda"
}

resource "aws_iam_role" "this" {
  name               = "ssh-host-key-signer"
  assume_role_policy = data.aws_iam_policy_document.policy.json
  path               = "/"
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
  ]

  inline_policy {
    name = "KMSKeySigning"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "kms:Sign",
            "kms:GetPublicKey",
          ]
          Resource = "arn:aws:kms:${var.region}:${var.account_id}:key/${var.kms_key_id}"
        }
      ]
    })
  }

  inline_policy {
    name = "LambdaEnvVarKMS"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
          ]
          Resource = data.aws_kms_key.lambda.arn
        }
      ]
    })
  }
}
