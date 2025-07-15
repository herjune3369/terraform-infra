
terraform {
  backend "s3" {
    bucket         = "herjune-terraform-state"
    key            = "devsecops-k8s/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "terraform-lock-table"
    encrypt        = true
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
