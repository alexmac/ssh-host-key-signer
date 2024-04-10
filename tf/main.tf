data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

module "ssh_host_key_signer" {
  source             = "./ssh_host_key_signer"
  account_id         = data.aws_caller_identity.current.account_id
  region             = data.aws_region.current.name
  private_subnet_ids = ["subnet-replaceme"]
  vpc_id             = "vpc-replaceme"
  kms_key_id         = "replaceme"
}
