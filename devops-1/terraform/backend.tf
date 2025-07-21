
terraform {
  backend "s3" {
    bucket         = "terraform-state-junheo-devops1-2024"
    key            = "devops-1/terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = "terraform-state-lock-devops1"
    encrypt        = true
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
