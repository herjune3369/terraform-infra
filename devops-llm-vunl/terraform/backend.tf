
terraform {
  backend "s3" {
    bucket         = "terraform-state-junheo-llm-vunl-2024"
    key            = "devops-llm-vunl/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "terraform-state-lock-llm-vunl"
    encrypt        = true
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
