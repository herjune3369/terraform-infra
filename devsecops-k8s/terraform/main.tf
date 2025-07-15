provider "aws" {
  region = "ap-northeast-2"
}

# 기존 VPC 사용
data "aws_vpc" "existing_vpc" {
  id = var.vpc_id
}

# 기존 서브넷 사용
data "aws_subnet" "public_subnet_a" {
  vpc_id = data.aws_vpc.existing_vpc.id
  filter {
    name   = "tag:Name"
    values = ["public-subnet-a"]
  }
}

data "aws_subnet" "public_subnet_b" {
  vpc_id = data.aws_vpc.existing_vpc.id
  filter {
    name   = "tag:Name"
    values = ["public-subnet-b"]
  }
}

data "aws_subnet" "private_subnet_c" {
  vpc_id = data.aws_vpc.existing_vpc.id
  filter {
    name   = "tag:Name"
    values = ["private-subnet-c"]
  }
}

# private-subnet-b는 존재하지 않으므로 제거

# NAT Gateway를 위한 EIP
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

# NAT Gateway
resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = data.aws_subnet.public_subnet_a.id

  tags = {
    Name = "nat-gateway"
  }
}

# 기존 Internet Gateway 사용
data "aws_internet_gateway" "existing_igw" {
  filter {
    name   = "attachment.vpc-id"
    values = [data.aws_vpc.existing_vpc.id]
  }
}

# Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = data.aws_vpc.existing_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = data.aws_internet_gateway.existing_igw.id
  }
}

# 라우트 테이블 연결은 이미 존재하므로 제거

resource "aws_route_table" "private_rt" {
  vpc_id = data.aws_vpc.existing_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "private-rt"
  }
}

# private 라우트 테이블 연결도 이미 존재하므로 제거

# private-subnet-b가 없으므로 제거

# RDS 설정 - public 서브넷을 사용하여 AZ 요구사항 충족
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "rds-subnet-group"
  subnet_ids = [data.aws_subnet.public_subnet_a.id, data.aws_subnet.public_subnet_b.id]

  tags = {
    Name = "rds-subnet-group"
  }
}

# 기존 Security Groups 사용
data "aws_security_group" "web_sg" {
  name   = "web-sg"
  vpc_id = data.aws_vpc.existing_vpc.id
}

data "aws_security_group" "alb_sg" {
  name   = "alb-sg"
  vpc_id = data.aws_vpc.existing_vpc.id
}

# rds-sg는 존재하지 않으므로 제거

# RDS 설정
resource "aws_db_instance" "flask_db" {
  identifier              = "flask-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_type            = "gp2"
  db_name                 = "saju"
  username                = "admin"
  password                = var.db_password
  skip_final_snapshot     = true
  multi_az                = false
  backup_retention_period = 0

  vpc_security_group_ids = [data.aws_security_group.web_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name

  tags = {
    Name = "flask-db"
  }
}

# SSH 키 페어
resource "aws_key_pair" "app_key" {
  key_name_prefix = "saju-app-key-"
  public_key      = var.public_key
}


# EC2 인스턴스 설정
resource "aws_instance" "web1" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnet.public_subnet_a.id
  vpc_security_group_ids      = [data.aws_security_group.web_sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.app_key.key_name

  tags = {
    Name = "webserver1"
  }
}

resource "aws_instance" "web2" {
  ami                         = var.ami_id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnet.public_subnet_b.id
  vpc_security_group_ids      = [data.aws_security_group.web_sg.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.app_key.key_name

  tags = {
    Name = "webserver2"
  }
}

# 기존 Target Group 사용
data "aws_lb_target_group" "existing_app_tg" {
  name = "app-tg"
}

# Load Balancer 설정
resource "aws_lb" "app_lb" {
  name               = "app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [data.aws_security_group.alb_sg.id]
  subnets            = [data.aws_subnet.public_subnet_a.id, data.aws_subnet.public_subnet_b.id]

  tags = {
    Name = "app-lb"
  }
}

resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = data.aws_lb_target_group.existing_app_tg.arn
  }
}

resource "aws_lb_target_group_attachment" "web1_attach" {
  target_group_arn = data.aws_lb_target_group.existing_app_tg.arn
  target_id        = aws_instance.web1.id
  port             = 5000
}

resource "aws_lb_target_group_attachment" "web2_attach" {
  target_group_arn = data.aws_lb_target_group.existing_app_tg.arn
  target_id        = aws_instance.web2.id
  port             = 5000
}

# EKS 클러스터를 위한 IAM 역할
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# EKS 노드 그룹을 위한 IAM 역할
resource "aws_iam_role" "eks_node_group_role" {
  name = "eks-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group_role.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group_role.name
}

# EKS 클러스터 보안 그룹
resource "aws_security_group" "eks_cluster_sg" {
  name_prefix = "eks-cluster-sg"
  vpc_id      = data.aws_vpc.existing_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-cluster-sg"
  }
}

resource "aws_security_group_rule" "eks_cluster_ingress_nodes" {
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.eks_cluster_sg.id
  source_security_group_id = aws_security_group.eks_cluster_sg.id
  to_port                  = 65535
  type                     = "ingress"
}

# EKS 클러스터
resource "aws_eks_cluster" "main" {
  name     = "devsecops-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = [data.aws_subnet.public_subnet_a.id, data.aws_subnet.public_subnet_b.id]
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]

  tags = {
    Name = "devsecops-eks-cluster"
  }
}

# EKS 노드 그룹
resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "devsecops-node-group"
  node_role_arn   = aws_iam_role.eks_node_group_role.arn
  subnet_ids      = [data.aws_subnet.public_subnet_a.id, data.aws_subnet.public_subnet_b.id]
  version         = aws_eks_cluster.main.version

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry_read_only
  ]

  tags = {
    Name = "devsecops-node-group"
  }
}
