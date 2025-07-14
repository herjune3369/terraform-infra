# S3 백엔드 인프라 자동 생성
resource "aws_s3_bucket" "terraform_state" {
  bucket = "devsecops-k8s-terraform-state-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "Terraform State Bucket"
    Environment = "DevSecOps"
    Project     = "devsecops-k8s"
  }
}

# S3 버킷 버전 관리
resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 버킷 암호화
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 버킷 퍼블릭 액세스 차단
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB 테이블 (상태 잠금용)
resource "aws_dynamodb_table" "terraform_locks" {
  name           = "terraform-state-lock-${random_string.bucket_suffix.result}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "Terraform State Lock Table"
    Environment = "DevSecOps"
    Project     = "devsecops-k8s"
  }
}

# 랜덤 문자열 생성 (버킷명 중복 방지)
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# 백엔드 설정 출력
output "backend_config" {
  description = "Backend configuration for Terraform"
  value = {
    bucket         = aws_s3_bucket.terraform_state.bucket
    key            = "terraform.tfstate"
    region         = "ap-northeast-2"
    dynamodb_table = aws_dynamodb_table.terraform_locks.name
    encrypt        = true
  }
} 