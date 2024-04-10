resource "aws_security_group" "sg" {
  name        = "lambda-ssh-host-key-signer"
  description = "Traffic from ssh-host-key-signer"
  vpc_id      = var.vpc_id
  tags = {
    Name = "lambda-ssh-host-key-signer"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_kms_key" "this" {
  description             = "private key for ssh hopst key signing"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "this" {
  name          = "alias/ssh-host-key-signer"
  target_key_id = aws_kms_key.this.key_id
}

resource "aws_lambda_function" "this" {
  function_name = "ssh-host-key-signing"

  role = aws_iam_role.this.arn

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.sg.id]
  }

  architectures = ["arm64"]
  package_type  = "Image"
  image_uri     = "${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/staging/ssh-host-key-signer:${local.docker_image_tag}"
  timeout       = 60

  environment {
    variables = {
      KEY_ARN             = aws_kms_key.this.arn
      CERT_VALIDITY_HOURS = 12
      DEBUG               = "false"
    }
  }
}
