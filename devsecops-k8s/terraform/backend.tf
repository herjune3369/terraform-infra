
terraform {
  # GitHub Actions에서는 로컬 백엔드 사용 (테스트용)
  # backend "s3" {
  #   bucket         = "terraform-state-junheo-20250611"
  #   key            = "ai-saju-app/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
